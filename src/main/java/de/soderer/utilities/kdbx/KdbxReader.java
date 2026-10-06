package de.soderer.utilities.kdbx;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import de.soderer.utilities.kdbx.data.KdbxBinary;
import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxCustomDataItem;
import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxEntryBinary;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat3;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat4;
import de.soderer.utilities.kdbx.data.KdbxMemoryProtection;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxTimes;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.utilities.HmacInputStream;
import de.soderer.utilities.kdbx.utilities.TypeHashLengthValueStructure;
import de.soderer.utilities.kdbx.utilities.Utilities;
import de.soderer.utilities.kdbx.utilities.Version;

/**
 * Reader for KeePass database files in the KDBX format (data format versions 3.x and 4.x).
 * <p>
 * Example:
 * <pre>
 * try (KdbxReader reader = new KdbxReader(new FileInputStream(file))) {
 * 	KdbxDatabase database = reader.readKdbxDatabase(password);
 * }
 * </pre>
 * <p>
 * The reader closes the given input stream after reading or when it is closed itself.
 * Only one database can be read per reader instance.
 */
public class KdbxReader implements AutoCloseable {
	/**
	 * Strict mode, which rejects unknown XML nodes and missing header hashes instead of ignoring them.
	 */
	private boolean strictMode = false;

	/**
	 * Stream of the KDBX file data.
	 */
	private final InputStream inputStream;

	/**
	 * Inner stream cipher for protected values, which must be applied to them in the order of their appearance in the XML document.
	 */
	private StreamCipher innerEncryptionCipher;

	/**
	 * Creates a reader for the given KDBX file data.
	 *
	 * @param inputStream stream of the KDBX file data, which will be closed by this reader
	 */
	public KdbxReader(final InputStream inputStream) {
		this.inputStream = inputStream;
	}

	/**
	 * Sets the strict mode, which rejects unknown XML nodes and missing header hashes instead of ignoring them.
	 *
	 * @param strictMode the strict mode, which rejects unknown XML nodes and missing header hashes instead of ignoring them
	 */
	public void setStrictMode(final boolean strictMode) {
		this.strictMode = strictMode;
	}

	/**
	 * Sets the strict mode, which rejects unknown XML nodes and missing header hashes instead of ignoring them and returns this object for method chaining.
	 *
	 * @param newStrictMode the strict mode, which rejects unknown XML nodes and missing header hashes instead of ignoring them
	 * @return this object
	 */
	public KdbxReader withStrictMode(final boolean newStrictMode) {
		setStrictMode(newStrictMode);
		return this;
	}

	/**
	 * Returns the strict mode, which rejects unknown XML nodes and missing header hashes instead of ignoring them.
	 *
	 * @return the strict mode, which rejects unknown XML nodes and missing header hashes instead of ignoring them
	 */
	public boolean isStrictMode() {
		return strictMode;
	}

	/**
	 * Reads the database, which is protected only by a password.
	 *
	 * @param password the master password of the database
	 * @return the decrypted database
	 * @throws Exception if the data is not a supported KDBX file, the password is wrong or the data is corrupted
	 */
	public KdbxDatabase readKdbxDatabase(final char[] password) throws Exception {
		return readKdbxDatabase(new KdbxCredentials(password));
	}

	/**
	 * Reads the database with the given credentials.
	 * <p>
	 * The credentials are remembered as salted fingerprint in the database, so that a later write with other credentials updates the "MasterKeyChanged" time.
	 *
	 * @param credentials the credentials (password and/or key file) of the database
	 * @return the decrypted database
	 * @throws Exception if the data is not a supported KDBX file, the credentials are wrong or the data is corrupted
	 */
	public KdbxDatabase readKdbxDatabase(final KdbxCredentials credentials) throws Exception {
		try (BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream)) {
			bufferedInputStream.mark(1024);
			final Version dataFormatVersion = KdbxHeaderFormat.readKdbxDataFormatVersion(bufferedInputStream);
			bufferedInputStream.reset();

			final KdbxDatabase database = new KdbxDatabase();
			final byte[] compositeKeyHash = credentials.createCompositeKeyHash();
			try {
				if (dataFormatVersion.getMajorVersionNumber() == 3) {
					readDataFormat3(compositeKeyHash, bufferedInputStream, dataFormatVersion, database);
				} else if (dataFormatVersion.getMajorVersionNumber() == 4) {
					readDataFormat4(compositeKeyHash, bufferedInputStream, dataFormatVersion, database);
				} else {
					throw new Exception("Major kdbx file data format version " + dataFormatVersion.getMajorVersionNumber() + " is not supported");
				}
				// Remember the credentials (as salted fingerprint only), so that the writer can detect a change of the master key
				database.rememberCredentials(compositeKeyHash);
				return database;
			} finally {
				Arrays.fill(compositeKeyHash, (byte) 0);
			}
		}
	}

	/**
	 * Reads the encrypted data of a KDBX 3.x file.
	 *
	 * @param compositeKeyHash hash of the composite key of the credentials
	 * @param dataInputStream stream positioned at the start of the file
	 * @param dataFormatVersion data format version of the file
	 * @param database database to fill with the read data
	 * @return the given database
	 * @throws Exception if decryption or parsing fails or the data is corrupted
	 */
	private KdbxDatabase readDataFormat3(final byte[] compositeKeyHash, final InputStream dataInputStream, final Version dataFormatVersion, final KdbxDatabase database) throws Exception {
		final Document document;
		final List<KdbxBinary> binaryAttachments = new ArrayList<>();
		database.setBinaryAttachments(binaryAttachments);
		final KdbxHeaderFormat3 headerFormat3 = KdbxHeaderFormat3.read(dataInputStream);
		database.setHeaderFormat(headerFormat3);
		final byte[] decryptionKey = headerFormat3.getEncryptionKey(compositeKeyHash);

		final byte[] encryptedData = Utilities.toByteArray(dataInputStream);
		byte[] decryptedData;
		try {
			final byte[] transformedKey = Utilities.concatArrays(headerFormat3.getMasterSeed(), decryptionKey);
			final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(transformedKey);
			final OuterEncryptionAlgorithm outerEncryptionAlgorithm = headerFormat3.getOuterEncryptionAlgorithm();
			if (outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_128 && outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_256) {
				throw new IllegalArgumentException("Cipher " + outerEncryptionAlgorithm + " is not implemented yet");
			}
			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			final SecretKeySpec secretKeySpec = new SecretKeySpec(finalKey, "AES");
			final AlgorithmParameterSpec paramSpec = new IvParameterSpec(headerFormat3.getEncryptionIV());
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, paramSpec);
			decryptedData = cipher.doFinal(encryptedData);
		} catch (final BadPaddingException e) {
			throw new Exception("KDBX database decryption failed. Maybe the given credentials are wrong.", e);
		} catch (final Exception e) {
			throw new Exception("KDBX database decryption failed. Maybe the given credentials are wrong.", e);
		}

		final ByteArrayInputStream decryptedPayloadStream = new ByteArrayInputStream(decryptedData);
		final byte[] expectedStartBytes = headerFormat3.getStreamStartBytes();
		final byte[] actualStartBytes = new byte[expectedStartBytes.length];
		final int readBytes = decryptedPayloadStream.read(actualStartBytes);
		if (readBytes != expectedStartBytes.length) {
			throw new Exception("Cannot read start bytes from payload: Not enough data left");
		} else if (!Arrays.equals(expectedStartBytes, actualStartBytes)) {
			throw new Exception("KDBX database decryption failed. Maybe the given credentials are wrong.");
		}

		// KDBX 3 HashedBlockStream: Blocks with consecutive block index, hash and data. A block with data length 0 terminates the payload.
		final ByteArrayOutputStream payloadData = new ByteArrayOutputStream();
		long expectedBlockIndex = 0;
		while (true) {
			final TypeHashLengthValueStructure nextBlock = TypeHashLengthValueStructure.read(decryptedPayloadStream, "SHA-256");
			final long blockIndex = nextBlock.getTypeId() & 0xFFFFFFFFL;
			if (blockIndex != expectedBlockIndex) {
				throw new Exception("Invalid payload block index " + blockIndex + ", expected " + expectedBlockIndex);
			} else if (nextBlock.getData().length == 0) {
				break;
			} else {
				payloadData.write(nextBlock.getData());
				expectedBlockIndex++;
			}
		}

		innerEncryptionCipher = createInnerEncryptionCipher(headerFormat3.getInnerEncryptionAlgorithm(), headerFormat3.getInnerEncryptionKeyBytes());

		byte[] decryptedPayload = payloadData.toByteArray();
		if (headerFormat3.isCompressData()) {
			decryptedPayload = Utilities.gunzip(decryptedPayload);
		}
		final byte[] decryptedXmlPayloadData = decryptedPayload;
		document = Utilities.parseXmlFile(decryptedXmlPayloadData);

		final Node rootNode = document.getDocumentElement();
		if (!"KeePassFile".equals(rootNode.getNodeName())) {
			if (strictMode) {
				throw new Exception("Unexpected xml root node name: " + rootNode.getNodeName());
			}
		}
		final NodeList childNodes = rootNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Meta".equals(childNode.getNodeName())) {
					database.setMeta(readKdbxMetaData(dataFormatVersion, childNode, binaryAttachments));
				} else if ("Root".equals(childNode.getNodeName())) {
					readRoot(dataFormatVersion, database, childNode);
				} else {
					if (strictMode) {
						throw new Exception("Unexpected data node name: " + childNode.getNodeName());
					}
				}
			}
		}

		// Check header hash by given value in decrypted kdbx xml meta data. Older KDBX 3 files do not contain this value.
		final String headerHash = database.getMeta().getHeaderHash();
		if (Utilities.isNotBlank(headerHash)) {
			final byte[] actualSha256 = MessageDigest.getInstance("SHA-256").digest(headerFormat3.getHeaderBytes());
			if (!MessageDigest.isEqual(actualSha256, Base64.getDecoder().decode(headerHash.trim()))) {
				throw new Exception("Outer header data corrupted, SHA-256 hashes do not match");
			}
		} else if (strictMode) {
			throw new Exception("Missing header hash in meta data");
		}

		database.getHeaderFormat().resetCryptoKeys();

		resolveBinaryReferences(database);

		return database;
	}

	/**
	 * Reads the encrypted data of a KDBX 4.x file.
	 *
	 * @param compositeKeyHash hash of the composite key of the credentials
	 * @param dataInputStream stream positioned at the start of the file
	 * @param dataFormatVersion data format version of the file
	 * @param database database to fill with the read data
	 * @return the given database
	 * @throws Exception if decryption or parsing fails or the data is corrupted
	 */
	private KdbxDatabase readDataFormat4(final byte[] compositeKeyHash, final InputStream dataInputStream, final Version dataFormatVersion, final KdbxDatabase database) throws Exception {
		final Document document;
		final KdbxHeaderFormat4 headerFormat4 = KdbxHeaderFormat4.read(dataInputStream);
		database.setHeaderFormat(headerFormat4);
		final byte[] decryptionKey = headerFormat4.getEncryptionKey(compositeKeyHash);

		// SHA-256 Hash verification of headerBytes
		final byte[] actualSha256 = MessageDigest.getInstance("SHA-256").digest(headerFormat4.getHeaderBytes());
		final byte[] expectedSha256 = dataInputStream.readNBytes(32);
		if (expectedSha256.length != 32) {
			throw new IllegalStateException("Cannot read header SHA-256 hash bytes");
		} else if (!MessageDigest.isEqual(actualSha256, expectedSha256)) {
			throw new Exception("Outer header data corrupted, SHA-256 hashes do not match");
		}

		final byte[] transformedKey = Utilities.concatArrays(headerFormat4.getMasterSeed(), decryptionKey);
		final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(transformedKey);

		final MessageDigest digest = MessageDigest.getInstance("SHA-512");
		digest.update(headerFormat4.getMasterSeed());
		digest.update(decryptionKey);
		final byte[] hmacKey = digest.digest(new byte[] { 0x01 });

		// HMAC-SHA-256 verification of headerBytes
		final byte[] expectedHeaderHMAC = dataInputStream.readNBytes(32);
		if (expectedHeaderHMAC.length != 32) {
			throw new IllegalStateException("Cannot read HMAC code bytes");
		}
		final byte[] indexBytes = Utilities.getLittleEndianBytes(0xFFFFFFFF_FFFFFFFFL);
		final MessageDigest headerVerificationKeyDigest = MessageDigest.getInstance("SHA-512");
		headerVerificationKeyDigest.update(indexBytes);
		final byte[] headerVerificationHmacKey = headerVerificationKeyDigest.digest(hmacKey);

		final Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		sha256_HMAC.init(new SecretKeySpec(headerVerificationHmacKey, "HmacSHA256"));
		sha256_HMAC.update(headerFormat4.getHeaderBytes());
		final byte[] actualHeaderHMAC = sha256_HMAC.doFinal();
		if (!MessageDigest.isEqual(actualHeaderHMAC, expectedHeaderHMAC)) {
			// When SHA-256 checksum was valid, then this means, that the credentials for decryption are wrong.
			throw new Exception("KDBX database decryption failed. Maybe the given credentials are wrong.");
		}

		try (InputStream hmacInputStream = new HmacInputStream(dataInputStream, hmacKey)) {
			final Cipher cipher;
			final SecretKeySpec secretKeySpec;
			final AlgorithmParameterSpec paramSpec;
			switch (headerFormat4.getOuterEncryptionAlgorithm()) {
				case AES_128:
				case AES_256:
					cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
					secretKeySpec = new SecretKeySpec(finalKey, "AES");
					paramSpec = new IvParameterSpec(headerFormat4.getEncryptionIV());
					break;
				case CHACHA20:
					// ChaCha20 (RFC 7539) with 96 bit nonce and initial block counter 0, provided by the JDK since Java 11
					cipher = Cipher.getInstance("ChaCha20");
					secretKeySpec = new SecretKeySpec(finalKey, "ChaCha20");
					paramSpec = new ChaCha20ParameterSpec(headerFormat4.getEncryptionIV(), 0);
					break;
				case TWOFISH:
					throw new IllegalArgumentException("Cipher " + headerFormat4.getOuterEncryptionAlgorithm() + " is not implemented yet");
				default:
					throw new IllegalArgumentException("Unknown cipher " + headerFormat4.getOuterEncryptionAlgorithm());
			}
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, paramSpec);
			try (InputStream cipherInputStream = headerFormat4.isCompressData() ? new GZIPInputStream(new CipherInputStream(hmacInputStream, cipher)) : new CipherInputStream(hmacInputStream, cipher)) {
				headerFormat4.readInnerHeader(cipherInputStream);
				database.setBinaryAttachments(headerFormat4.getBinaryAttachments());

				innerEncryptionCipher = createInnerEncryptionCipher(headerFormat4.getInnerEncryptionAlgorithm(), headerFormat4.getInnerEncryptionKeyBytes());

				final byte[] decryptedXmlPayloadData = Utilities.toByteArray(cipherInputStream);
				document = Utilities.parseXmlFile(decryptedXmlPayloadData);
			}

			// Read the remaining HMAC blocks, so that all of them are verified, including the terminating block, which detects truncated data
			final byte[] drainBuffer = new byte[4096];
			while (hmacInputStream.read(drainBuffer) != -1) {
				// skip trailing data
			}
		}

		final Node rootNode = document.getDocumentElement();
		if (!"KeePassFile".equals(rootNode.getNodeName())) {
			if (strictMode) {
				throw new Exception("Unexpected xml root node name: " + rootNode.getNodeName());
			}
		}
		final NodeList childNodes = rootNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Meta".equals(childNode.getNodeName())) {
					database.setMeta(readKdbxMetaData(dataFormatVersion, childNode, null));
				} else if ("Root".equals(childNode.getNodeName())) {
					readRoot(dataFormatVersion, database, childNode);
				} else {
					if (strictMode) {
						throw new Exception("Unexpected data node name: " + childNode.getNodeName());
					}
				}
			}
		}

		database.getHeaderFormat().resetCryptoKeys();

		resolveBinaryReferences(database);

		return database;
	}

	/**
	 * Creates the inner stream cipher for protected values.
	 *
	 * @param innerEncryptionAlgorithm algorithm of the inner stream cipher
	 * @param innerEncryptionKeyBytes key of the inner stream cipher as stored in the header
	 * @return the initialized stream cipher or null for algorithm NONE
	 * @throws Exception if the algorithm is not supported
	 */
	private StreamCipher createInnerEncryptionCipher(final InnerEncryptionAlgorithm innerEncryptionAlgorithm, final byte[] innerEncryptionKeyBytes) throws Exception {
		switch (innerEncryptionAlgorithm) {
			case SALSA20:
				if (innerEncryptionKeyBytes == null || innerEncryptionKeyBytes.length == 0) {
					throw new Exception("innerEncryptionKeyBytes must not be null or empty");
				} else {
					final byte[] key = MessageDigest.getInstance("SHA-256").digest(innerEncryptionKeyBytes);
					final KeyParameter keyparam = new KeyParameter(key);
					final byte[] initialVector = new byte[] { (byte) 0xE8, 0x30, 0x09, 0x4B, (byte) 0x97, 0x20, 0x5D, 0x2A };
					final ParametersWithIV params = new ParametersWithIV(keyparam, initialVector);
					innerEncryptionCipher = new Salsa20Engine();
					innerEncryptionCipher.init(false, params);
					return innerEncryptionCipher;
				}
			case CHACHA20:
				if (innerEncryptionKeyBytes == null || innerEncryptionKeyBytes.length == 0) {
					throw new Exception("innerEncryptionKeyBytes must not be null or empty");
				} else {
					final byte[] key = MessageDigest.getInstance("SHA-512").digest(innerEncryptionKeyBytes);
					final byte[] actualKey = Arrays.copyOfRange(key, 0, 32);
					final byte[] initialVector = Arrays.copyOfRange(key, 32, 32 + 12);
					final KeyParameter keyparam = new KeyParameter(actualKey);
					final ParametersWithIV params = new ParametersWithIV(keyparam, initialVector);
					innerEncryptionCipher = new ChaCha7539Engine();
					innerEncryptionCipher.init(false, params);
					return innerEncryptionCipher;
				}
			case ARC4_VARIANT:
				throw new Exception("Unsupported algorithm ARC4_VARIANT");
			case NONE:
				throw new Exception("Undefined algorithm");
			default:
				// no inner encryption
				return null;
		}
	}

	/**
	 * Reads the "Meta" node of the XML document.
	 *
	 * @param dataFormatVersion data format version of the file
	 * @param metaNode the "Meta" node
	 * @param binaryAttachments list to add the binaries of the meta data (KDBX 3.x only), or null if not applicable
	 * @return the meta data
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private KdbxMeta readKdbxMetaData(final Version dataFormatVersion, final Node metaNode, final List<KdbxBinary> binaryAttachments) throws Exception {
		final KdbxMeta kdbxMeta = new KdbxMeta();
		final NodeList childNodes = metaNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Generator".equals(childNode.getNodeName())) {
					kdbxMeta.setGenerator(parseStringValue(childNode));
				} else if ("HeaderHash".equals(childNode.getNodeName())) {
					kdbxMeta.setHeaderHash(parseStringValue(childNode));
				} else if ("SettingsChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setSettingsChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("DatabaseName".equals(childNode.getNodeName())) {
					kdbxMeta.setDatabaseName(parseStringValue(childNode));
				} else if ("DatabaseNameChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setDatabaseNameChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("DatabaseDescription".equals(childNode.getNodeName())) {
					kdbxMeta.setDatabaseDescription(parseStringValue(childNode));
				} else if ("DatabaseDescriptionChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setDatabaseDescriptionChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("DefaultUserName".equals(childNode.getNodeName())) {
					kdbxMeta.setDefaultUserName(parseStringValue(childNode));
				} else if ("DefaultUserNameChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setDefaultUserNameChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("MaintenanceHistoryDays".equals(childNode.getNodeName())) {
					kdbxMeta.setMaintenanceHistoryDays(parseIntegerValue(childNode));
				} else if ("Color".equals(childNode.getNodeName())) {
					kdbxMeta.setColor(parseStringValue(childNode));
				} else if ("MasterKeyChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setMasterKeyChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("MasterKeyChangeRec".equals(childNode.getNodeName())) {
					kdbxMeta.setMasterKeyChangeRec(parseIntegerValue(childNode));
				} else if ("MasterKeyChangeForce".equals(childNode.getNodeName())) {
					kdbxMeta.setMasterKeyChangeForce(parseIntegerValue(childNode));
				} else if ("MasterKeyChangeForceOnce".equals(childNode.getNodeName())) {
					kdbxMeta.setMasterKeyChangeForceOnce(parseBooleanValue(childNode));
				} else if ("RecycleBinEnabled".equals(childNode.getNodeName())) {
					kdbxMeta.setRecycleBinEnabled(parseBooleanValue(childNode));
				} else if ("RecycleBinUUID".equals(childNode.getNodeName())) {
					kdbxMeta.setRecycleBinUUID(parseUuidValue(childNode));
				} else if ("RecycleBinChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setRecycleBinChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("EntryTemplatesGroup".equals(childNode.getNodeName())) {
					kdbxMeta.setEntryTemplatesGroup(parseUuidValue(childNode));
				} else if ("EntryTemplatesGroupChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setEntryTemplatesGroupChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("HistoryMaxItems".equals(childNode.getNodeName())) {
					kdbxMeta.setHistoryMaxItems(parseIntegerValue(childNode));
				} else if ("HistoryMaxSize".equals(childNode.getNodeName())) {
					kdbxMeta.setHistoryMaxSize(parseIntegerValue(childNode));
				} else if ("LastSelectedGroup".equals(childNode.getNodeName())) {
					kdbxMeta.setLastSelectedGroup(parseUuidValue(childNode));
				} else if ("LastTopVisibleGroup".equals(childNode.getNodeName())) {
					kdbxMeta.setLastTopVisibleGroup(parseUuidValue(childNode));
				} else if ("Binaries".equals(childNode.getNodeName())) {
					if (binaryAttachments != null) {
						binaryAttachments.addAll(parseBinariesData(childNode));
					} else if (strictMode) {
						throw new Exception("Unexpected meta binaries in data format version " + dataFormatVersion);
					}
				} else if ("MemoryProtection".equals(childNode.getNodeName())) {
					kdbxMeta.setMemoryProtection(parseMemoryProtection(childNode));
				} else if ("CustomData".equals(childNode.getNodeName())) {
					kdbxMeta.setCustomData(parseCustomData(dataFormatVersion, childNode));
				} else if ("CustomIcons".equals(childNode.getNodeName())) {
					kdbxMeta.setCustomIcons(parseCustomIcons(childNode));
				} else {
					if (strictMode) {
						throw new Exception("Unexpected meta attribute node name: " + childNode.getNodeName());
					}
				}
			}
		}
		return kdbxMeta;
	}

	/**
	 * Reads the "MemoryProtection" node.
	 *
	 * @param memoryProtectionNode the "MemoryProtection" node
	 * @return the memory protection settings
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private KdbxMemoryProtection parseMemoryProtection(final Node memoryProtectionNode) throws Exception {
		final KdbxMemoryProtection memoryProtection = new KdbxMemoryProtection();
		final NodeList childNodes = memoryProtectionNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("ProtectTitle".equals(childNode.getNodeName())) {
					memoryProtection.setProtectTitle(parseBooleanValue(childNode));
				} else if ("ProtectUserName".equals(childNode.getNodeName())) {
					memoryProtection.setProtectUserName(parseBooleanValue(childNode));
				} else if ("ProtectPassword".equals(childNode.getNodeName())) {
					memoryProtection.setProtectPassword(parseBooleanValue(childNode));
				} else if ("ProtectURL".equals(childNode.getNodeName())) {
					memoryProtection.setProtectURL(parseBooleanValue(childNode));
				} else if ("ProtectNotes".equals(childNode.getNodeName())) {
					memoryProtection.setProtectNotes(parseBooleanValue(childNode));
				} else {
					if (strictMode) {
						throw new Exception("Unexpected meta memoryProtection node name: " + childNode.getNodeName());
					}
				}
			}
		}
		return memoryProtection;
	}

	/**
	 * Reads a "CustomData" node.
	 *
	 * @param dataFormatVersion data format version of the file
	 * @param customDataNode the "CustomData" node
	 * @return the custom data items
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private List<KdbxCustomDataItem> parseCustomData(final Version dataFormatVersion, final Node customDataNode)
			throws Exception {
		final List<KdbxCustomDataItem> customDataItems = new ArrayList<>();
		final NodeList childNodes = customDataNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Item".equals(childNode.getNodeName())) {
					customDataItems.add(parseCustomDataItem(dataFormatVersion, childNode));
				} else {
					if (strictMode) {
						throw new Exception("Unexpected customData node name: " + childNode.getNodeName());
					}
				}
			}
		}
		return customDataItems;
	}

	/**
	 * Reads an "Item" node of custom data.
	 *
	 * @param dataFormatVersion data format version of the file
	 * @param customDataItemNode the "Item" node
	 * @return the custom data item
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private KdbxCustomDataItem parseCustomDataItem(final Version dataFormatVersion, final Node customDataItemNode)
			throws Exception {
		final KdbxCustomDataItem customDataItem = new KdbxCustomDataItem();
		final NodeList childNodes = customDataItemNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Key".equals(childNode.getNodeName())) {
					customDataItem.setKey(parseStringValue(childNode));
				} else if ("Value".equals(childNode.getNodeName())) {
					customDataItem.setValue(parseStringValue(childNode));
				} else if ("LastModificationTime".equals(childNode.getNodeName())) {
					customDataItem.setLastModificationTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else {
					if (strictMode) {
						throw new Exception("Unexpected customData attribute node name: " + childNode.getNodeName());
					}
				}
			}
		}
		return customDataItem;
	}

	/**
	 * Reads the "Binaries" node of the meta data (KDBX 3.x).
	 *
	 * @param binaryNode the "Binaries" node
	 * @return the binaries
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private List<KdbxBinary> parseBinariesData(final Node binaryNode) throws Exception {
		final List<KdbxBinary> binaryItems = new ArrayList<>();
		final NodeList binaryNodes = binaryNode.getChildNodes();
		for (int i = 0; i < binaryNodes.getLength(); i++) {
			final Node binaryChildNode = binaryNodes.item(i);
			if (binaryChildNode.getNodeType() != Node.TEXT_NODE) {
				if ("Binary".equals(binaryChildNode.getNodeName())) {
					final String idString = Utilities.getAttributeValue(binaryChildNode, "ID");
					final int id;
					try {
						id = Integer.parseInt(idString);
					} catch (final NumberFormatException e) {
						throw new Exception("Invalid binary id: " + idString, e);
					}
					final boolean compressed = "True".equals(Utilities.getAttributeValue(binaryChildNode, "Compressed"));
					final byte[] data = decodeBinaryValue(binaryChildNode);
					binaryItems.add(new KdbxBinary().withId(id).withCompressed(compressed).withData(data));
				} else {
					if (strictMode) {
						throw new Exception("Unexpected binary node name: " + binaryChildNode.getNodeName());
					}
				}
			}
		}
		return binaryItems;
	}

	/**
	 * Reads the "CustomIcons" node.
	 *
	 * @param customIconsNode the "CustomIcons" node
	 * @return the icon data by icon UUID
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private Map<KdbxUUID, byte[]> parseCustomIcons(final Node customIconsNode) throws Exception {
		final Map<KdbxUUID, byte[]> customIcons = new LinkedHashMap<>();
		final NodeList customIconsChildNodes = customIconsNode.getChildNodes();
		for (int i = 0; i < customIconsChildNodes.getLength(); i++) {
			final Node customIconNode = customIconsChildNodes.item(i);
			if (customIconNode.getNodeType() != Node.TEXT_NODE) {
				if ("Icon".equals(customIconNode.getNodeName())) {
					final KdbxUUID uuid = parseUuidValue(Utilities.getChildNodesMap(customIconNode).get("UUID"));
					final String dataBase64String = Utilities.getNodeValue(Utilities.getChildNodesMap(customIconNode).get("Data"));
					final byte[] data = Base64.getDecoder().decode(dataBase64String);
					customIcons.put(uuid, data);
				} else {
					if (strictMode) {
						throw new Exception("Unexpected custom icon node name: " + customIconNode.getNodeName());
					}
				}
			}
		}
		return customIcons;
	}

	/**
	 * Reads the "Root" node with groups, entries and deleted objects.
	 *
	 * @param dataFormatVersion data format version of the file
	 * @param database database to fill
	 * @param rootNode the "Root" node
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private void readRoot(final Version dataFormatVersion, final KdbxDatabase database, final Node rootNode)
			throws Exception {
		final NodeList childNodes = rootNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Group".equals(childNode.getNodeName())) {
					database.getGroups().add(readGroup(dataFormatVersion, childNode));
				} else if ("Entry".equals(childNode.getNodeName())) {
					database.getEntries().add(readEntry(dataFormatVersion, childNode));
				} else if ("DeletedObjects".equals(childNode.getNodeName())) {
					readDeletedObjects(dataFormatVersion, database, childNode);
				} else {
					if (strictMode) {
						throw new Exception("Unexpected root data node name: " + childNode.getNodeName());
					}
				}
			}
		}
	}

	/**
	 * Reads the "DeletedObjects" node.
	 *
	 * @param dataFormatVersion data format version of the file
	 * @param database database to fill
	 * @param childNode the "DeletedObjects" node
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private void readDeletedObjects(final Version dataFormatVersion, final KdbxDatabase database, final Node childNode)
			throws Exception {
		final NodeList deletedObjectsChildNodes = childNode.getChildNodes();
		for (int j = 0; j < deletedObjectsChildNodes.getLength(); j++) {
			final Node deletedObjectsChildNode = deletedObjectsChildNodes.item(j);
			if (deletedObjectsChildNode.getNodeType() != Node.TEXT_NODE) {
				if ("DeletedObject".equals(deletedObjectsChildNode.getNodeName())) {
					KdbxUUID uuid = null;
					ZonedDateTime deletionTime = null;
					final NodeList deletedObjectChildNodes = deletedObjectsChildNode.getChildNodes();
					for (int k = 0; k < deletedObjectChildNodes.getLength(); k++) {
						final Node deletedObjectChildNode = deletedObjectChildNodes.item(k);
						if (deletedObjectChildNode.getNodeType() != Node.TEXT_NODE) {
							if ("UUID".equals(deletedObjectChildNode.getNodeName())) {
								uuid = parseUuidValue(deletedObjectChildNode);
							} else if ("DeletionTime".equals(deletedObjectChildNode.getNodeName())) {
								deletionTime = parseDateTimeValue(dataFormatVersion, deletedObjectChildNode);
							} else {
								if (strictMode) {
									throw new Exception("Unexpected deleted objects data node name: " + childNode.getNodeName());
								}
							}
						}
					}
					if (uuid == null) {
						throw new Exception("Invalid deleted object node: Missing uuid");
					} else if (deletionTime == null) {
						throw new Exception("Invalid deleted object node for uuid '" + uuid.toHex() + "': Missing deletionTime");
					} else {
						database.getDeletedObjects().put(uuid, deletionTime);
					}
				} else {
					if (strictMode) {
						throw new Exception("Unexpected deleted object data node name: " + deletedObjectsChildNode.getNodeName());
					}
				}
			}
		}
	}

	/**
	 * Reads a "Group" node including its subgroups and entries.
	 *
	 * @param dataFormatVersion data format version of the file
	 * @param groupNode the "Group" node
	 * @return the group
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private KdbxGroup readGroup(final Version dataFormatVersion, final Node groupNode) throws Exception {
		final KdbxGroup group = new KdbxGroup();
		final NodeList childNodes = groupNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("UUID".equals(childNode.getNodeName())) {
					group.setUuid(parseUuidValue(childNode));
				} else if ("Name".equals(childNode.getNodeName())) {
					group.setName(parseStringValue(childNode));
				} else if ("Notes".equals(childNode.getNodeName())) {
					group.setNotes(parseStringValue(childNode));
				} else if ("IconID".equals(childNode.getNodeName())) {
					group.setIconID(parseIntegerValue(childNode));
				} else if ("IsExpanded".equals(childNode.getNodeName())) {
					group.setExpanded(parseBooleanValue(childNode));
				} else if ("DefaultAutoTypeSequence".equals(childNode.getNodeName())) {
					group.setDefaultAutoTypeSequence(parseStringValue(childNode));
				} else if ("EnableAutoType".equals(childNode.getNodeName())) {
					group.setEnableAutoTypeSetting(parseNullableBooleanValue(childNode));
				} else if ("EnableSearching".equals(childNode.getNodeName())) {
					group.setEnableSearchingSetting(parseNullableBooleanValue(childNode));
				} else if ("LastTopVisibleEntry".equals(childNode.getNodeName())) {
					group.setLastTopVisibleEntry(parseUuidValue(childNode));
				} else if ("Times".equals(childNode.getNodeName())) {
					group.setTimes(readKdbxTimes(dataFormatVersion, childNode));
				} else if ("Group".equals(childNode.getNodeName())) {
					group.getGroups().add(readGroup(dataFormatVersion, childNode));
				} else if ("Entry".equals(childNode.getNodeName())) {
					group.getEntries().add(readEntry(dataFormatVersion, childNode));
				} else if ("CustomIconUUID".equals(childNode.getNodeName())) {
					group.setCustomIconUuid(parseUuidValue(childNode));
				} else if ("CustomData".equals(childNode.getNodeName())) {
					group.setCustomData(parseCustomData(dataFormatVersion, childNode));
				} else {
					if (strictMode) {
						throw new Exception("Unexpected group data node name: " + childNode.getNodeName());
					}
				}
			}
		}
		return group;
	}

	/**
	 * Reads a "Times" node.
	 *
	 * @param dataFormatVersion data format version of the file
	 * @param timesNode the "Times" node
	 * @return the times
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private KdbxTimes readKdbxTimes(final Version dataFormatVersion, final Node timesNode) throws Exception {
		final KdbxTimes times = new KdbxTimes();
		final NodeList childNodes = timesNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("CreationTime".equals(childNode.getNodeName())) {
					times.setCreationTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("LastModificationTime".equals(childNode.getNodeName())) {
					times.setLastModificationTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("LastAccessTime".equals(childNode.getNodeName())) {
					times.setLastAccessTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("ExpiryTime".equals(childNode.getNodeName())) {
					times.setExpiryTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("Expires".equals(childNode.getNodeName())) {
					times.setExpires(parseBooleanValue(childNode));
				} else if ("UsageCount".equals(childNode.getNodeName())) {
					times.setUsageCount(parseIntegerValue(childNode));
				} else if ("LocationChanged".equals(childNode.getNodeName())) {
					times.setLocationChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else {
					if (strictMode) {
						throw new Exception("Unexpected times data node name: " + childNode.getNodeName());
					}
				}
			}
		}
		return times;
	}

	/**
	 * Reads an "Entry" node including its history entries.
	 *
	 * @param dataFormatVersion data format version of the file
	 * @param entryNode the "Entry" node
	 * @return the entry
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private KdbxEntry readEntry(final Version dataFormatVersion, final Node entryNode) throws Exception {
		final KdbxEntry entry = new KdbxEntry();
		final NodeList childNodes = entryNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("UUID".equals(childNode.getNodeName())) {
					entry.setUuid(parseUuidValue(childNode));
				} else if ("IconID".equals(childNode.getNodeName())) {
					entry.setIconID(parseIntegerValue(childNode));
				} else if ("ForegroundColor".equals(childNode.getNodeName())) {
					entry.setForegroundColor(parseStringValue(childNode));
				} else if ("BackgroundColor".equals(childNode.getNodeName())) {
					entry.setBackgroundColor(parseStringValue(childNode));
				} else if ("OverrideURL".equals(childNode.getNodeName())) {
					entry.setOverrideURL(parseStringValue(childNode));
				} else if ("Tags".equals(childNode.getNodeName())) {
					entry.setTags(parseStringValue(childNode));
				} else if ("Times".equals(childNode.getNodeName())) {
					entry.setTimes(readKdbxTimes(dataFormatVersion, childNode));
				} else if ("String".equals(childNode.getNodeName())) {
					parseKeyValue(entry, childNode);
				} else if ("Binary".equals(childNode.getNodeName())) {
					entry.getBinaries().add(readEntryBinary(childNode));
				} else if ("AutoType".equals(childNode.getNodeName())) {
					boolean enabled = false;
					String dataTransferObfuscation = null;
					String defaultSequence = null;
					String window = null;
					String keystrokeSequence = null;
					final NodeList autoTypeChildNodes = childNode.getChildNodes();
					for (int j = 0; j < autoTypeChildNodes.getLength(); j++) {
						final Node autoTypeChildNode = autoTypeChildNodes.item(j);
						if (autoTypeChildNode.getNodeType() != Node.TEXT_NODE) {
							if ("Enabled".equals(autoTypeChildNode.getNodeName())) {
								enabled = parseBooleanValue(autoTypeChildNode);
							} else if ("DataTransferObfuscation".equals(autoTypeChildNode.getNodeName())) {
								dataTransferObfuscation = parseStringValue(autoTypeChildNode);
							} else if ("DefaultSequence".equals(autoTypeChildNode.getNodeName())) {
								defaultSequence = parseStringValue(autoTypeChildNode);
							} else if ("Association".equals(autoTypeChildNode.getNodeName())) {
								final NodeList associationChildNodes = autoTypeChildNode.getChildNodes();
								for (int k = 0; k < associationChildNodes.getLength(); k++) {
									final Node associationChildNode = associationChildNodes.item(k);
									if (associationChildNode.getNodeType() != Node.TEXT_NODE) {
										if ("Window".equals(associationChildNode.getNodeName())) {
											window = parseStringValue(associationChildNode);
										} else if ("KeystrokeSequence".equals(associationChildNode.getNodeName())) {
											keystrokeSequence = parseStringValue(associationChildNode);
										} else {
											if (strictMode) {
												throw new Exception("Unexpected association data node name: "
														+ associationChildNode.getNodeName());
											}
										}
									}
								}
							} else {
								if (strictMode) {
									throw new Exception("Unexpected autotype data node name: " + autoTypeChildNode.getNodeName());
								}
							}
						}
					}
					entry.setAutoType(enabled, dataTransferObfuscation, defaultSequence, window, keystrokeSequence);
				} else if ("History".equals(childNode.getNodeName())) {
					final NodeList historyChildNodes = childNode.getChildNodes();
					for (int j = 0; j < historyChildNodes.getLength(); j++) {
						final Node historyChildNode = historyChildNodes.item(j);
						if (historyChildNode.getNodeType() != Node.TEXT_NODE) {
							if ("Entry".equals(historyChildNode.getNodeName())) {
								entry.getHistory().add(readEntry(dataFormatVersion, historyChildNode));
							} else {
								if (strictMode) {
									throw new Exception("Unexpected history entry data node name: "
											+ historyChildNode.getNodeName());
								}
							}
						}
					}
				} else if ("CustomIconUUID".equals(childNode.getNodeName())) {
					entry.setCustomIconUuid(parseUuidValue(childNode));
				} else if ("CustomData".equals(childNode.getNodeName())) {
					entry.setCustomData(parseCustomData(dataFormatVersion, childNode));
				} else {
					if (strictMode) {
						throw new Exception("Unexpected entry data node name: " + childNode.getNodeName());
					}
				}
			}
		}
		return entry;
	}

	/**
	 * Returns the text content of a node.
	 *
	 * @param stringValueNode element or text node
	 * @return the text or null for an element without content
	 */
	private static String parseStringValue(final Node stringValueNode) {
		if (stringValueNode.getNodeType() == Node.ELEMENT_NODE) {
			// getTextContent also joins text split into several nodes (e.g. by CDATA sections)
			return stringValueNode.hasChildNodes() ? stringValueNode.getTextContent() : null;
		} else {
			return stringValueNode.getNodeValue();
		}
	}

	/**
	 * Reads a "String" node of an entry and stores its key, value and protection flag in the entry.
	 * Protected values are decrypted with the inner stream cipher.
	 *
	 * @param entry entry to store the item in
	 * @param keyValueNode the "String" node
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private void parseKeyValue(final KdbxEntry entry, final Node keyValueNode) throws Exception {
		String key = null;
		String value = null;
		boolean protectedItemKey = false;
		final NodeList childNodes = keyValueNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Key".equals(childNode.getNodeName())) {
					key = parseStringValue(childNode);
				} else if ("Value".equals(childNode.getNodeName())) {
					value = parseStringValue(childNode);
					boolean isProtected = false;
					final NamedNodeMap attributes = childNode.getAttributes();
					if (attributes != null) {
						for (int j = 0; j < attributes.getLength(); j++) {
							final Node attribute = attributes.item(j);
							if ("Protected".equals(attribute.getNodeName())) {
								isProtected = "True".equals(attribute.getNodeValue());
								break;
							}
						}
					}
					if (isProtected) {
						protectedItemKey = true;
					}
					if (isProtected && value != null && innerEncryptionCipher != null) {
						value = new String(decryptProtectedData(Base64.getDecoder().decode(value)), StandardCharsets.UTF_8);
					}
				} else {
					if (strictMode) {
						throw new Exception("Unexpected key value data node name: " + childNode.getNodeName());
					}
				}
			}
		}
		if (key == null) {
			throw new Exception("Invalid key value data node: Missing key");
		} else {
			entry.setItem(key, value);
			if (protectedItemKey) {
				entry.setItemProtected(key, true);
			}
		}
	}

	/**
	 * Reads a "Binary" node of an entry, which either references a binary of the database or contains the data itself.
	 *
	 * @param entryBinaryNode the "Binary" node
	 * @return the entry binary
	 * @throws Exception if the data is invalid or unknown in strict mode
	 */
	private KdbxEntryBinary readEntryBinary(final Node entryBinaryNode) throws Exception {
		String key = null;
		Integer refID = null;
		byte[] data = null;
		final NodeList entryBinaryNodes = entryBinaryNode.getChildNodes();
		for (int i = 0; i < entryBinaryNodes.getLength(); i++) {
			final Node entryBinaryChildNode = entryBinaryNodes.item(i);
			if (entryBinaryChildNode.getNodeType() != Node.TEXT_NODE) {
				if ("Key".equals(entryBinaryChildNode.getNodeName())) {
					key = parseStringValue(entryBinaryChildNode);
				} else if ("Value".equals(entryBinaryChildNode.getNodeName())) {
					final String refIdString = Utilities.getAttributeValue(entryBinaryChildNode, "Ref");
					if (Utilities.isNotBlank(refIdString)) {
						try {
							refID = Integer.parseInt(refIdString.trim());
						} catch (final NumberFormatException e) {
							throw new Exception("Invalid binary reference id: " + refIdString, e);
						}
					} else {
						data = decodeBinaryValue(entryBinaryChildNode);
						if ("True".equals(Utilities.getAttributeValue(entryBinaryChildNode, "Compressed"))) {
							data = Utilities.gunzip(data);
						}
					}
				} else {
					if (strictMode) {
						throw new Exception("Unexpected binary data node name: " + entryBinaryChildNode.getNodeName());
					}
				}
			}
		}
		if (key == null) {
			throw new Exception("Invalid key value data node: Missing key");
		} else {
			if (strictMode && refID != null && data != null) {
				throw new Exception("Unexpected entry binary data using refID and data at the same time. ID: " + refID);
			}
			final KdbxEntryBinary entryBinary = new KdbxEntryBinary();
			entryBinary.setKey(key);
			if (refID != null) {
				entryBinary.setRefId(refID);
			}
			if (data != null) {
				entryBinary.setCompressedData(Utilities.gzip(data));
			}
			return entryBinary;
		}
	}

	/**
	 * Decodes the base64 data of a binary value node and decrypts it, if it is marked as protected.
	 * The compression flag is not evaluated here.
	 *
	 * @param binaryValueNode node with base64 data and optional "Protected" attribute
	 * @return the decoded (and decrypted) data
	 * @throws Exception if the data is no valid base64
	 */
	private byte[] decodeBinaryValue(final Node binaryValueNode) throws Exception {
		final String dataBase64String = parseStringValue(binaryValueNode);
		final byte[] data = dataBase64String == null ? new byte[0] : Base64.getMimeDecoder().decode(dataBase64String);
		if ("True".equals(Utilities.getAttributeValue(binaryValueNode, "Protected")) && innerEncryptionCipher != null) {
			return decryptProtectedData(data);
		} else {
			return data;
		}
	}

	/**
	 * Decrypts protected data with the inner stream cipher.
	 * The inner stream cipher must be applied to all protected values in the order of their appearance in the XML document.
	 *
	 * @param encryptedData the encrypted data
	 * @return the decrypted data
	 */
	private byte[] decryptProtectedData(final byte[] encryptedData) {
		final byte[] output = new byte[encryptedData.length];
		innerEncryptionCipher.processBytes(encryptedData, 0, encryptedData.length, output, 0);
		return output;
	}

	/**
	 * Resolves the references of entry attachments (including attachments of history entries) to the binary attachments of the database.
	 * References use the binary id, which in KDBX 4 is the position in the inner header.
	 *
	 * @param database the database
	 * @throws Exception if a referenced binary does not exist or cannot be compressed
	 */
	private static void resolveBinaryReferences(final KdbxDatabase database) throws Exception {
		for (final KdbxEntry entry : database.getAllEntriesIncludingHistory()) {
			for (final KdbxEntryBinary binary : entry.getBinaries()) {
				if (binary.getRefId() != null) {
					KdbxBinary databaseBinary = null;
					if (database.getBinaryAttachments() != null) {
						for (final KdbxBinary binaryAttachment : database.getBinaryAttachments()) {
							if (binaryAttachment.getId() == binary.getRefId()) {
								databaseBinary = binaryAttachment;
								break;
							}
						}
					}
					if (databaseBinary == null) {
						throw new Exception("Cannot find referenced binary id: " + binary.getRefId());
					} else if (databaseBinary.isCompressed()) {
						binary.setCompressedData(databaseBinary.getData());
					} else {
						binary.setCompressedData(Utilities.gzip(databaseBinary.getData()));
					}
				}
			}
		}
	}

	/**
	 * Parses a date time value: ISO text in KDBX 3.x, base64 encoded seconds since 0001-01-01 in KDBX 4.x.
	 *
	 * @param kdbxVersion data format version of the file
	 * @param node node with the value
	 * @return the date time or null for an empty value
	 * @throws Exception if the value is invalid
	 */
	private static ZonedDateTime parseDateTimeValue(final Version kdbxVersion, final Node node) throws Exception {
		final String stringValue = parseStringValue(node);
		if (stringValue == null || "".equals(stringValue.trim())) {
			return null;
		} else if (kdbxVersion.getMajorVersionNumber() < 4) {
			return ZonedDateTime.from(DateTimeFormatter.ISO_DATE_TIME.parse(stringValue));
		} else {
			try {
				final byte[] secondsArray = Base64.getDecoder().decode(stringValue);
				final long elapsedSeconds = Utilities.readLongFromLittleEndianBytes(secondsArray);
				if (elapsedSeconds < 0) {
					throw new Exception("Long value of seconds since 0001-01-001 00:00:00 UTC overflowed: " + elapsedSeconds);
				} else {
					return ZonedDateTime.of(1, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC")).plusSeconds(elapsedSeconds).withZoneSameInstant(ZoneId.systemDefault());
				}
			} catch (final Exception e) {
				throw new Exception("Invalid DateTime base64 value: " + stringValue, e);
			}
		}
	}

	/**
	 * Parses a boolean value ("True" or "False").
	 *
	 * @param node node with the value
	 * @return true for "True" (case insensitive), otherwise false
	 */
	private static boolean parseBooleanValue(final Node node) {
		final String stringValue = parseStringValue(node);
		return stringValue != null && "True".equalsIgnoreCase(stringValue.trim());
	}

	/**
	 * Parses a boolean value, which may also have the value "null" (e.g. "inherit from parent group").
	 *
	 * @param node node with the value
	 * @return true, false or null for "null" or an empty value
	 */
	private static Boolean parseNullableBooleanValue(final Node node) {
		final String stringValue = parseStringValue(node);
		if (stringValue == null || Utilities.isBlank(stringValue) || "null".equalsIgnoreCase(stringValue.trim())) {
			return null;
		} else {
			return "True".equalsIgnoreCase(stringValue.trim());
		}
	}

	/**
	 * Parses an integer value.
	 *
	 * @param node node with the value
	 * @return the integer value
	 * @throws Exception if the value is no valid integer
	 */
	private static int parseIntegerValue(final Node node) throws Exception {
		final String stringValue = parseStringValue(node);
		if (stringValue == null || "".equals(stringValue.trim())) {
			throw new Exception("Invalid empty integer value");
		} else {
			try {
				return Integer.parseInt(stringValue);
			} catch (final NumberFormatException e) {
				throw new Exception("Invalid integer value: " + stringValue, e);
			}
		}
	}

	/**
	 * Parses a base64 encoded UUID value.
	 *
	 * @param node node with the value
	 * @return the UUID or null for an empty value
	 */
	private static KdbxUUID parseUuidValue(final Node node) {
		return KdbxUUID.fromBase64(parseStringValue(node));
	}

	/**
	 * Closes the input stream.
	 *
	 * @throws IOException if closing the stream fails
	 */
	@Override
	public void close() throws IOException {
		if (inputStream != null) {
			inputStream.close();
		}
	}
}
