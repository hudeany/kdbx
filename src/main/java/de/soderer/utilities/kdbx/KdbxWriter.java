package de.soderer.utilities.kdbx;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

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
import de.soderer.utilities.kdbx.utilities.HmacOutputStream;
import de.soderer.utilities.kdbx.utilities.TypeHashLengthValueStructure;
import de.soderer.utilities.kdbx.utilities.Utilities;
import de.soderer.utilities.kdbx.utilities.Version;

/**
 * Writer for KeePass database files in the KDBX format (data format versions 3.1 and 4.0).
 * <p>
 * Example:
 * <pre>
 * try (KdbxWriter writer = new KdbxWriter(new FileOutputStream(file))) {
 * 	writer.writeKdbxDatabase(database, password);
 * }
 * </pre>
 * <p>
 * Binary attachments are stored only once, even if several entries contain the same data.
 * In data format version 3.1 they are stored in the meta data binaries, in version 4.0 in the inner header.
 * <p>
 * Each write generates new random values for master seed, encryption IV, key derivation salt and inner stream key.
 * The writer closes the given output stream after writing or when it is closed itself.
 */
public class KdbxWriter implements AutoCloseable {
	/**
	 * Block size of the KDBX 3.x HashedBlockStream, as used by KeePass.
	 */
	private static final int PAYLOAD_BLOCK_SIZE = 1024 * 1024;

	/**
	 * Stream for the KDBX file data.
	 */
	private final OutputStream outputStream;

	/**
	 * Additional item keys, which are always written as protected values in addition to those defined by the memory protection settings of the database.
	 */
	private Set<String> additionalKeyNamesToEncrypt = null;

	/**
	 * Creates a writer for KDBX file data.
	 *
	 * @param outputStream stream for the KDBX file data, which will be closed by this writer
	 */
	public KdbxWriter(final OutputStream outputStream) {
		this.outputStream = outputStream;
	}

	/**
	 * Sets the additional item keys, which are always written as protected values in addition to those defined by the memory protection settings of the database.
	 *
	 * @param additionalKeyNamesToEncrypt the additional item keys, which are always written as protected values in addition to those defined by the memory protection settings of the database
	 */
	public void setAdditionalKeyNamesToEncrypt(final Set<String> additionalKeyNamesToEncrypt) {
		this.additionalKeyNamesToEncrypt = additionalKeyNamesToEncrypt;
	}

	/**
	 * Sets the additional item keys, which are always written as protected values in addition to those defined by the memory protection settings of the database and returns this object for method chaining.
	 *
	 * @param newAdditionalKeyNamesToEncrypt the additional item keys, which are always written as protected values in addition to those defined by the memory protection settings of the database
	 * @return this object
	 */
	public KdbxWriter withAdditionalKeyNamesToEncrypt(final Set<String> newAdditionalKeyNamesToEncrypt) {
		setAdditionalKeyNamesToEncrypt(newAdditionalKeyNamesToEncrypt);
		return this;
	}

	/**
	 * Writes the database in data format version 4.0, protected by a password.
	 *
	 * @param database the database to write
	 * @param password the master password
	 * @throws Exception if the database is invalid or encryption fails
	 */
	public void writeKdbxDatabase(final KdbxDatabase database, final char[] password) throws Exception {
		writeKdbxDatabase(database, null, new KdbxCredentials(password));
	}

	/**
	 * Writes the database in the data format of the given header, protected by a password.
	 *
	 * @param database the database to write
	 * @param headerFormat header format, which defines data format version and encryption settings, or null for the default version 4.0 header
	 * @param password the master password
	 * @throws Exception if the database is invalid or encryption fails
	 */
	public void writeKdbxDatabase(final KdbxDatabase database, final KdbxHeaderFormat headerFormat, final char[] password) throws Exception {
		writeKdbxDatabase(database, headerFormat, new KdbxCredentials(password));
	}

	/**
	 * Writes the database in data format version 4.0.
	 *
	 * @param database the database to write
	 * @param credentials the credentials (password and/or key file)
	 * @throws Exception if the database is invalid or encryption fails
	 */
	public void writeKdbxDatabase(final KdbxDatabase database, final KdbxCredentials credentials) throws Exception {
		writeKdbxDatabase(database, null, credentials);
	}

	/**
	 * Writes the database in the data format of the given header.
	 * <p>
	 * The database is validated first (see {@link KdbxDatabase#validate()}).
	 * The "MasterKeyChanged" time of the meta data is only updated, if the credentials differ from those of the last read or write of this database object.
	 *
	 * @param database the database to write
	 * @param headerFormat header format, which defines data format version and encryption settings, or null for the default version 4.0 header
	 * @param credentials the credentials (password and/or key file)
	 * @throws Exception if the database is invalid or encryption fails
	 */
	public void writeKdbxDatabase(final KdbxDatabase database, KdbxHeaderFormat headerFormat, final KdbxCredentials credentials) throws Exception {
		database.validate();

		if (headerFormat == null) {
			headerFormat = new KdbxHeaderFormat4();
		}

		final byte[] compositeKeyHash = credentials.createCompositeKeyHash();
		try {
			// MasterKeyChanged is only updated, if the credentials differ from the ones used for the last read or write of this database
			if (database.getMeta().getMasterKeyChanged() == null || !database.isSameCredentials(compositeKeyHash)) {
				database.getMeta().setMasterKeyChanged(ZonedDateTime.now());
			}

			writeDatabase(database, headerFormat, compositeKeyHash);

			database.rememberCredentials(compositeKeyHash);
		} finally {
			Arrays.fill(compositeKeyHash, (byte) 0);
		}
	}

	/**
	 * Writes the database with new random crypto values in the header.
	 *
	 * @param database the validated database
	 * @param headerFormat header format
	 * @param compositeKeyHash hash of the composite key of the credentials
	 * @throws Exception if encryption fails
	 */
	private void writeDatabase(final KdbxDatabase database, final KdbxHeaderFormat headerFormat, final byte[] compositeKeyHash) throws Exception {
		// Every write needs new random master seed, encryption IV, KDF salt and inner stream key.
		// Reusing them (e.g. when saving the same database twice) would reuse key and nonce of the stream ciphers.
		headerFormat.resetCryptoKeys();

		if (headerFormat instanceof KdbxHeaderFormat3) {
			writeEncryptedDataVersion3((KdbxHeaderFormat3) headerFormat, outputStream, compositeKeyHash, database);
		} else {
			writeEncryptedDataVersion4((KdbxHeaderFormat4) headerFormat, outputStream, compositeKeyHash, database);
		}
	}

	/**
	 * Writes the database in data format version 3.1: header, AES-CBC encrypted HashedBlockStream with the (compressed) XML payload.
	 *
	 * @param headerFormat header format
	 * @param dataOutputStream stream for the file data
	 * @param compositeKeyHash hash of the composite key of the credentials
	 * @param database the database
	 * @throws Exception if encryption fails
	 */
	private void writeEncryptedDataVersion3(final KdbxHeaderFormat3 headerFormat, final OutputStream dataOutputStream, final byte[] compositeKeyHash, final KdbxDatabase database) throws Exception {
		final byte[] outerHeadersDataBytes = headerFormat.getHeaderBytes();
		dataOutputStream.write(outerHeadersDataBytes);

		final byte[] sha256Hash = MessageDigest.getInstance("SHA-256").digest(outerHeadersDataBytes);
		database.getMeta().setHeaderHash(Base64.getEncoder().encodeToString(sha256Hash));

		final StreamCipher innerEncryptionCipher = createInnerEncryptionCipher(headerFormat.getInnerEncryptionAlgorithm(), headerFormat.getInnerEncryptionKeyBytes());

		final Document document = createXmlDocument(database, headerFormat.getDataFormatVersion(), innerEncryptionCipher);

		final ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
		payloadStream.write(headerFormat.getStreamStartBytes());

		byte[] decryptedPayload = convertXML2ByteArray(document, StandardCharsets.UTF_8);

		if (headerFormat.isCompressData()) {
			decryptedPayload = Utilities.gzip(decryptedPayload);
		}
		// KDBX 3 HashedBlockStream: Blocks of 1 MiB with consecutive block index, terminated by an empty block
		int blockIndex = 0;
		for (int offset = 0; offset < decryptedPayload.length; offset += PAYLOAD_BLOCK_SIZE) {
			final byte[] blockData = Arrays.copyOfRange(decryptedPayload, offset, Math.min(decryptedPayload.length, offset + PAYLOAD_BLOCK_SIZE));
			TypeHashLengthValueStructure.write(payloadStream, blockIndex++, blockData, "SHA-256");
		}
		TypeHashLengthValueStructure.write(payloadStream, blockIndex, null, "SHA-256");

		final byte[] encryptionKey = headerFormat.getEncryptionKey(compositeKeyHash);

		byte[] encryptedData;
		try {
			final byte[] transformedKey = Utilities.concatArrays(headerFormat.getMasterSeed(), encryptionKey);
			final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(transformedKey);
			final OuterEncryptionAlgorithm outerEncryptionAlgorithm = headerFormat.getOuterEncryptionAlgorithm();
			if (outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_128 && outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_256) {
				throw new IllegalArgumentException("Cipher " + outerEncryptionAlgorithm + " is not implemented yet");
			}

			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			final SecretKeySpec secretKeySpec = new SecretKeySpec(finalKey, "AES");
			final AlgorithmParameterSpec paramSpec = new IvParameterSpec(headerFormat.getEncryptionIV());
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);
			encryptedData = cipher.doFinal(payloadStream.toByteArray());
		} catch (final Exception e) {
			throw new Exception("Encryption failed", e);
		}

		dataOutputStream.write(encryptedData);
		dataOutputStream.flush();
		dataOutputStream.close();
	}

	/**
	 * Writes the database in data format version 4.0: header with SHA-256 and HMAC, encrypted HMAC block stream with inner header and (compressed) XML payload.
	 *
	 * @param headerFormat header format
	 * @param dataOutputStream stream for the file data
	 * @param compositeKeyHash hash of the composite key of the credentials
	 * @param database the database
	 * @throws Exception if encryption fails
	 */
	private void writeEncryptedDataVersion4(final KdbxHeaderFormat4 headerFormat, final OutputStream dataOutputStream, final byte[] compositeKeyHash, final KdbxDatabase database) throws Exception {
		final byte[] outerHeadersDataBytes = headerFormat.getHeaderBytes();
		dataOutputStream.write(outerHeadersDataBytes);

		final byte[] sha256Hash = MessageDigest.getInstance("SHA-256").digest(outerHeadersDataBytes);
		dataOutputStream.write(sha256Hash);

		final byte[] encryptionKey = headerFormat.getEncryptionKey(compositeKeyHash);
		final byte[] transformedKey = Utilities.concatArrays(headerFormat.getMasterSeed(), encryptionKey);
		final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(transformedKey);

		final MessageDigest digest = MessageDigest.getInstance("SHA-512");
		digest.update(headerFormat.getMasterSeed());
		digest.update(encryptionKey);
		final byte[] hmacKey = digest.digest(new byte[] { 0x01 });

		final byte[] indexBytes = Utilities.getLittleEndianBytes(0xFFFFFFFF_FFFFFFFFL);
		final MessageDigest headerVerificationKeyDigest = MessageDigest.getInstance("SHA-512");
		headerVerificationKeyDigest.update(indexBytes);
		final byte[] headerVerificationHmacKey = headerVerificationKeyDigest.digest(hmacKey);

		final Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		sha256_HMAC.init(new SecretKeySpec(headerVerificationHmacKey, "HmacSHA256"));
		sha256_HMAC.update(outerHeadersDataBytes, 0, outerHeadersDataBytes.length);
		final byte[] actualHeaderHMAC = sha256_HMAC.doFinal();
		dataOutputStream.write(actualHeaderHMAC);

		try (HmacOutputStream hmacOutputStream = new HmacOutputStream(dataOutputStream, hmacKey)) {
			final Cipher cipher;
			final SecretKeySpec secretKeySpec;
			final AlgorithmParameterSpec paramSpec;
			switch (headerFormat.getOuterEncryptionAlgorithm()) {
				case AES_128:
				case AES_256:
					cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
					secretKeySpec = new SecretKeySpec(finalKey, "AES");
					paramSpec = new IvParameterSpec(headerFormat.getEncryptionIV());
					break;
				case CHACHA20:
					// ChaCha20 (RFC 7539) with 96 bit nonce and initial block counter 0, provided by the JDK since Java 11
					cipher = Cipher.getInstance("ChaCha20");
					secretKeySpec = new SecretKeySpec(finalKey, "ChaCha20");
					paramSpec = new ChaCha20ParameterSpec(headerFormat.getEncryptionIV(), 0);
					break;
				case TWOFISH:
					throw new IllegalArgumentException("Cipher " + headerFormat.getOuterEncryptionAlgorithm() + " is not implemented yet");
				default:
					throw new IllegalArgumentException("Unknown cipher " + headerFormat.getOuterEncryptionAlgorithm());
			}
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);
			try (OutputStream cipherOutputStream = headerFormat.isCompressData() ? new GZIPOutputStream(new CipherOutputStream(hmacOutputStream, cipher)) : new CipherOutputStream(hmacOutputStream, cipher)) {
				cipherOutputStream.write(headerFormat.getInnerHeaderBytes(database));

				final StreamCipher innerEncryptionCipher = createInnerEncryptionCipher(headerFormat.getInnerEncryptionAlgorithm(), headerFormat.getInnerEncryptionKeyBytes());

				final Document document = createXmlDocument(database, headerFormat.getDataFormatVersion(), innerEncryptionCipher);

				cipherOutputStream.write(convertXML2ByteArray(document, StandardCharsets.UTF_8));
				cipherOutputStream.flush();
			}
		}
		dataOutputStream.close();
	}

	/**
	 * Creates the XML document of the database. Protected values are encrypted with the inner stream cipher in document order.
	 *
	 * @param database the database
	 * @param dataFormatVersion data format version
	 * @param innerEncryptionCipher inner stream cipher or null for no protection
	 * @return the XML document
	 * @throws Exception if the document cannot be created
	 */
	private Document createXmlDocument(final KdbxDatabase database, final Version dataFormatVersion, final StreamCipher innerEncryptionCipher) throws Exception {
		final Set<String> keyNamesToEncrypt = new HashSet<>();
		final KdbxMemoryProtection memoryProtection = database.getMeta().getMemoryProtection();
		if (memoryProtection.isProtectTitle()) {
			keyNamesToEncrypt.add("Title");
		}
		if (memoryProtection.isProtectUserName()) {
			keyNamesToEncrypt.add("UserName");
		}
		if (memoryProtection.isProtectPassword()) {
			keyNamesToEncrypt.add("Password");
		}
		if (memoryProtection.isProtectURL()) {
			keyNamesToEncrypt.add("URL");
		}
		if (memoryProtection.isProtectNotes()) {
			keyNamesToEncrypt.add("Notes");
		}
		keyNamesToEncrypt.add("KPRPC JSON");
		if (additionalKeyNamesToEncrypt != null) {
			keyNamesToEncrypt.addAll(additionalKeyNamesToEncrypt);
		}

		final Document document = Utilities.createNewDocument();
		final Node xmlDocumentRootNode = Utilities.appendNode(document, "KeePassFile");
		final Node metaNode = writeMetaNode(dataFormatVersion, xmlDocumentRootNode, database.getMeta());
		writeRootNode(innerEncryptionCipher, keyNamesToEncrypt, dataFormatVersion, xmlDocumentRootNode, database);

		if (dataFormatVersion.getMajorVersionNumber() < 4) {
			writeBinariesToMeta(metaNode, database);
		}
		return document;
	}

	/**
	 * Serializes an XML node as UTF-8 or other encoded text.
	 *
	 * @param pDocument the node to serialize
	 * @param encoding the character encoding
	 * @return the serialized XML data
	 * @throws Exception if the transformation fails
	 */
	public static byte[] convertXML2ByteArray(final Node pDocument, final Charset encoding) throws Exception {
		TransformerFactory transformerFactory = null;
		Transformer transformer = null;
		DOMSource domSource = null;
		StreamResult result = null;

		try {
			transformerFactory = TransformerFactory.newInstance();
			if (transformerFactory == null) {
				throw new Exception("TransformerFactory error");
			}

			transformer = transformerFactory.newTransformer();
			if (transformer == null) {
				throw new Exception("Transformer error");
			}

			if (encoding != null) {
				transformer.setOutputProperty(OutputKeys.ENCODING, encoding.name());
			} else {
				transformer.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
			}

			domSource = new DOMSource(pDocument);
			try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
				result = new StreamResult(outputStream);
				transformer.transform(domSource, result);
				return outputStream.toByteArray();
			}
		} catch (final TransformerFactoryConfigurationError e) {
			throw new Exception("TransformerFactoryConfigurationError", e);
		} catch (final TransformerConfigurationException e) {
			throw new Exception("TransformerConfigurationException", e);
		} catch (final TransformerException e) {
			throw new Exception("TransformerException", e);
		}
	}

	/**
	 * Writes the "Meta" node.
	 *
	 * @param dataFormatVersion data format version
	 * @param xmlDocumentRootNode root node of the document
	 * @param meta the meta data
	 * @return the created "Meta" node
	 */
	private static Node writeMetaNode(final Version dataFormatVersion, final Node xmlDocumentRootNode, final KdbxMeta meta) {
		final Node metaNode = Utilities.appendNode(xmlDocumentRootNode, "Meta");
		if (meta.getGenerator() != null) {
			Utilities.appendTextValueNode(metaNode, "Generator", meta.getGenerator());
		}
		if (dataFormatVersion.getMajorVersionNumber() < 4 && meta.getHeaderHash() != null) {
			Utilities.appendTextValueNode(metaNode, "HeaderHash", meta.getHeaderHash());
		}
		if (meta.getSettingsChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "SettingsChanged", formatDateTimeValue(dataFormatVersion, meta.getSettingsChanged()));
		}
		Utilities.appendTextValueNode(metaNode, "DatabaseName", meta.getDatabaseName());
		if (meta.getDatabaseNameChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "DatabaseNameChanged", formatDateTimeValue(dataFormatVersion, meta.getDatabaseNameChanged()));
		}
		Utilities.appendTextValueNode(metaNode, "DatabaseDescription", meta.getDatabaseDescription());
		if (meta.getDatabaseDescriptionChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "DatabaseDescriptionChanged", formatDateTimeValue(dataFormatVersion, meta.getDatabaseDescriptionChanged()));
		}
		Utilities.appendTextValueNode(metaNode, "DefaultUserName", meta.getDefaultUserName());
		if (meta.getDefaultUserNameChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "DefaultUserNameChanged", formatDateTimeValue(dataFormatVersion, meta.getDefaultUserNameChanged()));
		}
		if (meta.getMaintenanceHistoryDays() > -1) {
			Utilities.appendTextValueNode(metaNode, "MaintenanceHistoryDays", formatIntegerValue(meta.getMaintenanceHistoryDays()));
		}
		Utilities.appendTextValueNode(metaNode, "Color", meta.getColor());
		if (meta.getMasterKeyChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "MasterKeyChanged", formatDateTimeValue(dataFormatVersion, meta.getMasterKeyChanged()));
		}
		if (meta.getMasterKeyChangeRec() > -1) {
			Utilities.appendTextValueNode(metaNode, "MasterKeyChangeRec", formatIntegerValue(meta.getMasterKeyChangeRec()));
		}
		if (meta.getMasterKeyChangeForce() > -1) {
			Utilities.appendTextValueNode(metaNode, "MasterKeyChangeForce", formatIntegerValue(meta.getMasterKeyChangeForce()));
		}
		if (meta.isMasterKeyChangeForceOnce()) {
			Utilities.appendTextValueNode(metaNode, "MasterKeyChangeForceOnce", formatBooleanValue(true));
		}
		Utilities.appendTextValueNode(metaNode, "RecycleBinEnabled", formatBooleanValue(meta.isRecycleBinEnabled()));
		if (meta.getRecycleBinUUID() != null) {
			Utilities.appendTextValueNode(metaNode, "RecycleBinUUID", formatKdbxUUIDValue(meta.getRecycleBinUUID()));
		}
		if (meta.getRecycleBinChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "RecycleBinChanged", formatDateTimeValue(dataFormatVersion, meta.getRecycleBinChanged()));
		}
		if (meta.getEntryTemplatesGroup() != null) {
			Utilities.appendTextValueNode(metaNode, "EntryTemplatesGroup", formatKdbxUUIDValue(meta.getEntryTemplatesGroup()));
		}
		if (meta.getEntryTemplatesGroupChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "EntryTemplatesGroupChanged", formatDateTimeValue(dataFormatVersion, meta.getEntryTemplatesGroupChanged()));
		}
		if (meta.getHistoryMaxItems() > -1) {
			Utilities.appendTextValueNode(metaNode, "HistoryMaxItems", formatIntegerValue(meta.getHistoryMaxItems()));
		}
		if (meta.getHistoryMaxSize() > -1) {
			Utilities.appendTextValueNode(metaNode, "HistoryMaxSize", formatIntegerValue(meta.getHistoryMaxSize()));
		}
		if (meta.getLastSelectedGroup() != null) {
			Utilities.appendTextValueNode(metaNode, "LastSelectedGroup", formatKdbxUUIDValue(meta.getLastSelectedGroup()));
		}
		if (meta.getLastTopVisibleGroup() != null) {
			Utilities.appendTextValueNode(metaNode, "LastTopVisibleGroup", formatKdbxUUIDValue(meta.getLastTopVisibleGroup()));
		}
		writeMemoryProtectionNode(metaNode, meta.getMemoryProtection());

		if (meta.getCustomIcons() != null && meta.getCustomIcons().size() > 0) {
			writeCustomIcons(metaNode, meta.getCustomIcons());
		}
		if (meta.getCustomData() != null && meta.getCustomData().size() > 0) {
			writeCustomData(dataFormatVersion, metaNode, meta.getCustomData());
		}
		return metaNode;
	}

	/**
	 * Writes the "CustomIcons" node.
	 *
	 * @param metaNode the "Meta" node
	 * @param customIcons the icon data by icon UUID
	 */
	private static void writeCustomIcons(final Node metaNode, final Map<KdbxUUID, byte[]> customIcons) {
		final Node customIconsNode = Utilities.appendNode(metaNode, "CustomIcons");
		for (final Entry<KdbxUUID, byte[]> customIcon : customIcons.entrySet()) {
			final Node iconNode = Utilities.appendNode(customIconsNode, "Icon");
			Utilities.appendTextValueNode(iconNode, "UUID", formatKdbxUUIDValue(customIcon.getKey()));
			Utilities.appendTextValueNode(iconNode, "Data", Base64.getEncoder().encodeToString(customIcon.getValue()));
		}
	}

	/**
	 * Writes the "MemoryProtection" node.
	 *
	 * @param metaNode the "Meta" node
	 * @param memoryProtection the memory protection settings
	 */
	private static void writeMemoryProtectionNode(final Node metaNode, final KdbxMemoryProtection memoryProtection) {
		final Node memoryProtectionNode = Utilities.appendNode(metaNode, "MemoryProtection");
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectTitle", formatBooleanValue(memoryProtection.isProtectTitle()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectUserName", formatBooleanValue(memoryProtection.isProtectUserName()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectPassword", formatBooleanValue(memoryProtection.isProtectPassword()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectURL", formatBooleanValue(memoryProtection.isProtectURL()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectNotes", formatBooleanValue(memoryProtection.isProtectNotes()));
	}

	/**
	 * Writes the "Root" node with groups, entries and deleted objects.
	 *
	 * @param innerEncryptionCipher inner stream cipher or null for no protection
	 * @param keyNamesToEncrypt item keys, which are always protected
	 * @param dataFormatVersion data format version
	 * @param xmlDocumentRootNode root node of the document
	 * @param database the database
	 */
	private void writeRootNode(final StreamCipher innerEncryptionCipher, final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node xmlDocumentRootNode, final KdbxDatabase database) {
		final Node rootNode = Utilities.appendNode(xmlDocumentRootNode, "Root");
		for (final KdbxGroup group : database.getGroups()) {
			writeGroupNode(innerEncryptionCipher, keyNamesToEncrypt, dataFormatVersion, rootNode, group);
		}
		for (final KdbxEntry entry : database.getEntries()) {
			writeEntryNode(innerEncryptionCipher, keyNamesToEncrypt, dataFormatVersion, rootNode, entry);
		}
		if (database.getDeletedObjects().size() > 0) {
			writeDeletedObjects(dataFormatVersion, rootNode, database.getDeletedObjects());
		}
	}

	/**
	 * Writes the binary attachments to the "Binaries" node of the meta data (KDBX 3.x).
	 *
	 * @param metaNode the "Meta" node
	 * @param database the database
	 * @throws Exception if the data cannot be compressed
	 */
	private static void writeBinariesToMeta(final Node metaNode, final KdbxDatabase database) throws Exception {
		final Node binariesNode = Utilities.appendNode(metaNode, "Binaries");
		for (final KdbxBinary binaryAttachment : database.getBinaryAttachments()) {
			final Element binaryNode = Utilities.appendNode(binariesNode, "Binary");
			Utilities.appendAttribute(binaryNode, "ID", formatIntegerValue(binaryAttachment.getId()));
			if (!binaryAttachment.isCompressed()) {
				binaryAttachment.setData(Utilities.gzip(binaryAttachment.getData()));
				binaryAttachment.setCompressed(true);
			}
			Utilities.appendAttribute(binaryNode, "Compressed", formatBooleanValue(binaryAttachment.isCompressed()));
			final String valueString = Base64.getEncoder().encodeToString(binaryAttachment.getData());
			binaryNode.appendChild(binaryNode.getOwnerDocument().createTextNode(valueString));
		}
	}

	/**
	 * Writes a "Group" node including its subgroups and entries.
	 *
	 * @param innerEncryptionCipher inner stream cipher or null for no protection
	 * @param keyNamesToEncrypt item keys, which are always protected
	 * @param dataFormatVersion data format version
	 * @param baseNode parent node
	 * @param group the group
	 */
	private void writeGroupNode(final StreamCipher innerEncryptionCipher, final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node baseNode, final KdbxGroup group) {
		final Node groupNode = Utilities.appendNode(baseNode, "Group");
		Utilities.appendTextValueNode(groupNode, "UUID", formatKdbxUUIDValue(group.getUuid()));
		Utilities.appendTextValueNode(groupNode, "Name", group.getName());
		Utilities.appendTextValueNode(groupNode, "Notes", group.getNotes());
		if (group.getIconID() != null) {
			Utilities.appendTextValueNode(groupNode, "IconID", formatIntegerValue(group.getIconID()));
		}
		Utilities.appendTextValueNode(groupNode, "IsExpanded", formatBooleanValue(group.isExpanded()));
		Utilities.appendTextValueNode(groupNode, "DefaultAutoTypeSequence", group.getDefaultAutoTypeSequence());
		Utilities.appendTextValueNode(groupNode, "EnableAutoType", formatNullableBooleanValue(group.getEnableAutoTypeSetting()));
		Utilities.appendTextValueNode(groupNode, "EnableSearching", formatNullableBooleanValue(group.getEnableSearchingSetting()));
		if (group.getLastTopVisibleEntry() != null) {
			Utilities.appendTextValueNode(groupNode, "LastTopVisibleEntry", formatKdbxUUIDValue(group.getLastTopVisibleEntry()));
		}

		writeTimes(dataFormatVersion, groupNode, group.getTimes());

		for (final KdbxGroup subGroup : group.getGroups()) {
			writeGroupNode(innerEncryptionCipher, keyNamesToEncrypt, dataFormatVersion, groupNode, subGroup);
		}

		for (final KdbxEntry entry : group.getEntries()) {
			writeEntryNode(innerEncryptionCipher, keyNamesToEncrypt, dataFormatVersion, groupNode, entry);
		}

		if (group.getCustomIconUuid() != null) {
			Utilities.appendTextValueNode(groupNode, "CustomIconUUID", formatKdbxUUIDValue(group.getCustomIconUuid()));
		}

		if (group.getCustomData() != null) {
			writeCustomData(dataFormatVersion, groupNode, group.getCustomData());
		}
	}

	/**
	 * Writes a "CustomData" node.
	 *
	 * @param dataFormatVersion data format version
	 * @param baseNode parent node
	 * @param customData the custom data items
	 */
	private static void writeCustomData(final Version dataFormatVersion, final Node baseNode, final List<KdbxCustomDataItem> customData) {
		final Node customDataNode = Utilities.appendNode(baseNode, "CustomData");
		for (final KdbxCustomDataItem customDataItem : customData) {
			final Node customDataItemNode = Utilities.appendNode(customDataNode, "Item");
			Utilities.appendTextValueNode(customDataItemNode, "Key", customDataItem.getKey());
			Utilities.appendTextValueNode(customDataItemNode, "Value", customDataItem.getValue());
			if (customDataItem.getLastModificationTime() != null) {
				Utilities.appendTextValueNode(customDataItemNode, "LastModificationTime", formatDateTimeValue(dataFormatVersion, customDataItem.getLastModificationTime()));
			}
		}
	}

	/**
	 * Writes an "Entry" node including its history entries.
	 * Items are protected, if their key is in keyNamesToEncrypt or they are marked as protected in the entry.
	 *
	 * @param innerEncryptionCipher inner stream cipher or null for no protection
	 * @param keyNamesToEncrypt item keys, which are always protected
	 * @param dataFormatVersion data format version
	 * @param baseNode parent node
	 * @param entry the entry
	 */
	private void writeEntryNode(final StreamCipher innerEncryptionCipher, final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node baseNode, final KdbxEntry entry) {
		final Node entryNode = Utilities.appendNode(baseNode, "Entry");
		Utilities.appendTextValueNode(entryNode, "UUID", formatKdbxUUIDValue(entry.getUuid()));
		if (entry.getIconID() != null) {
			Utilities.appendTextValueNode(entryNode, "IconID", formatIntegerValue(entry.getIconID()));
		}
		Utilities.appendTextValueNode(entryNode, "ForegroundColor", entry.getForegroundColor());
		Utilities.appendTextValueNode(entryNode, "BackgroundColor", entry.getBackgroundColor());
		Utilities.appendTextValueNode(entryNode, "OverrideURL", entry.getOverrideURL());
		Utilities.appendTextValueNode(entryNode, "Tags", entry.getTags());

		writeTimes(dataFormatVersion, entryNode, entry.getTimes());

		for (final Entry<String, Object> itemEntry : entry.getItems().entrySet()) {
			final Node itemNode = Utilities.appendNode(entryNode, "String");
			Utilities.appendTextValueNode(itemNode, "Key", itemEntry.getKey());
			if (keyNamesToEncrypt.contains(itemEntry.getKey()) || entry.isItemProtected(itemEntry.getKey())) {
				String value = itemEntry.getValue() == null ? null : itemEntry.getValue().toString();
				if (value != null && innerEncryptionCipher != null) {
					final byte[] data = value.getBytes(StandardCharsets.UTF_8);
					final byte[] output = new byte[data.length];
					innerEncryptionCipher.processBytes(data, 0, data.length, output, 0);
					value = Base64.getEncoder().encodeToString(output);
				}
				final Node valueNode = Utilities.appendTextValueNode(itemNode, "Value", value);
				Utilities.appendAttribute((Element) valueNode, "Protected", "True");
			} else {
				Utilities.appendTextValueNode(itemNode, "Value", itemEntry.getValue() == null ? null : itemEntry.getValue().toString());
			}
		}

		if (entry.getBinaries() != null && entry.getBinaries().size() > 0) {
			for (final KdbxEntryBinary entryBinary : entry.getBinaries()) {
				final Element binaryNode = Utilities.appendNode(entryNode, "Binary");
				Utilities.appendTextValueNode(binaryNode, "Key", entryBinary.getKey());
				final Element valueNode = Utilities.appendNode(binaryNode, "Value");
				Utilities.appendAttribute(valueNode, "Ref", Integer.toString(entryBinary.getRefId()));
			}
		}

		final Node autoTypeNode = Utilities.appendNode(entryNode, "AutoType");
		Utilities.appendTextValueNode(autoTypeNode, "Enabled", formatBooleanValue(entry.isAutoTypeEnabled()));
		Utilities.appendTextValueNode(autoTypeNode, "DataTransferObfuscation", entry.getAutoTypeDataTransferObfuscation());
		Utilities.appendTextValueNode(autoTypeNode, "DefaultSequence", entry.getAutoTypeDefaultSequence());
		if (Utilities.isNotBlank(entry.getAutoTypeAssociationWindow()) || Utilities.isNotBlank(entry.getAutoTypeAssociationKeystrokeSequence())) {
			final Node autoTypeAssociationNode = Utilities.appendNode(autoTypeNode, "Association");
			Utilities.appendTextValueNode(autoTypeAssociationNode, "Window", entry.getAutoTypeAssociationWindow());
			Utilities.appendTextValueNode(autoTypeAssociationNode, "KeystrokeSequence", entry.getAutoTypeAssociationKeystrokeSequence());
		}

		final Node historyNode = Utilities.appendNode(entryNode, "History");
		for (final KdbxEntry historyEntry : entry.getHistory()) {
			writeEntryNode(innerEncryptionCipher, keyNamesToEncrypt, dataFormatVersion, historyNode, historyEntry);
		}

		if (entry.getCustomIconUuid() != null) {
			Utilities.appendTextValueNode(entryNode, "CustomIconUUID", formatKdbxUUIDValue(entry.getCustomIconUuid()));
		}

		if (entry.getCustomData() != null) {
			writeCustomData(dataFormatVersion, entryNode, entry.getCustomData());
		}
	}

	/**
	 * Writes the "DeletedObjects" node.
	 *
	 * @param dataFormatVersion data format version
	 * @param baseNode parent node
	 * @param deletedObjects deletion times by UUID
	 */
	private static void writeDeletedObjects(final Version dataFormatVersion, final Node baseNode, final Map<KdbxUUID, ZonedDateTime> deletedObjects) {
		final Node deletedObjectsNode = Utilities.appendNode(baseNode, "DeletedObjects");
		for (final Entry<KdbxUUID, ZonedDateTime> deletedObject : deletedObjects.entrySet()) {
			final Node deletedObjectNode = Utilities.appendNode(deletedObjectsNode, "DeletedObject");
			Utilities.appendTextValueNode(deletedObjectNode, "UUID", formatKdbxUUIDValue(deletedObject.getKey()));
			Utilities.appendTextValueNode(deletedObjectNode, "DeletionTime", formatDateTimeValue(dataFormatVersion, deletedObject.getValue()));
		}
	}

	/**
	 * Writes a "Times" node.
	 *
	 * @param dataFormatVersion data format version
	 * @param baseNode parent node
	 * @param times the times
	 */
	private static void writeTimes(final Version dataFormatVersion, final Node baseNode, final KdbxTimes times) {
		final Node timesNode = Utilities.appendNode(baseNode, "Times");
		Utilities.appendTextValueNode(timesNode, "LastModificationTime", formatDateTimeValue(dataFormatVersion, times.getLastModificationTime()));
		Utilities.appendTextValueNode(timesNode, "CreationTime", formatDateTimeValue(dataFormatVersion, times.getCreationTime()));
		Utilities.appendTextValueNode(timesNode, "LastAccessTime", formatDateTimeValue(dataFormatVersion, times.getLastAccessTime()));
		Utilities.appendTextValueNode(timesNode, "ExpiryTime", formatDateTimeValue(dataFormatVersion, times.getExpiryTime()));
		Utilities.appendTextValueNode(timesNode, "Expires", formatBooleanValue(times.isExpires()));
		Utilities.appendTextValueNode(timesNode, "UsageCount", formatIntegerValue(times.getUsageCount()));
		Utilities.appendTextValueNode(timesNode, "LocationChanged", formatDateTimeValue(dataFormatVersion, times.getLocationChanged()));
	}

	/**
	 * Creates the inner stream cipher for protected values.
	 *
	 * @param innerEncryptionAlgorithm algorithm of the inner stream cipher
	 * @param innerEncryptionKeyBytes key of the inner stream cipher as stored in the header
	 * @return the initialized stream cipher or null for algorithm NONE
	 * @throws Exception if the algorithm is not supported
	 */
	private static StreamCipher createInnerEncryptionCipher(final InnerEncryptionAlgorithm innerEncryptionAlgorithm, final byte[] innerEncryptionKeyBytes) throws Exception {
		switch (innerEncryptionAlgorithm) {
			case SALSA20:
				if (innerEncryptionKeyBytes == null || innerEncryptionKeyBytes.length == 0) {
					throw new Exception("innerEncryptionKeyBytes must not be null or empty");
				} else {
					final byte[] key = MessageDigest.getInstance("SHA-256").digest(innerEncryptionKeyBytes);
					final KeyParameter keyparam = new KeyParameter(key);
					final byte[] initialVector = new byte[] { (byte) 0xE8, 0x30, 0x09, 0x4B, (byte) 0x97, 0x20, 0x5D, 0x2A };
					final ParametersWithIV params = new ParametersWithIV(keyparam, initialVector);
					final StreamCipher innerEncryptionCipher = new Salsa20Engine();
					innerEncryptionCipher.init(true, params);
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
					final StreamCipher innerEncryptionCipher = new ChaCha7539Engine();
					innerEncryptionCipher.init(true, params);
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
	 * Formats a date time value: UTC ISO text with seconds precision in KDBX 3.x ("2024-01-31T12:34:56Z"), base64 encoded seconds since 0001-01-01 in KDBX 4.x.
	 *
	 * @param dataFormatVersion data format version
	 * @param dateTimeValue the date time or null
	 * @return the formatted value or an empty string for null
	 */
	private static String formatDateTimeValue(final Version dataFormatVersion, final ZonedDateTime dateTimeValue) {
		if (dateTimeValue == null) {
			return "";
		} else if (dataFormatVersion.getMajorVersionNumber() < 4) {
			// KeePass format: UTC with seconds precision, e.g. "2024-01-31T12:34:56Z"
			return DateTimeFormatter.ISO_INSTANT.format(dateTimeValue.toInstant().truncatedTo(ChronoUnit.SECONDS));
		} else {
			final Duration duration = Duration.between(ZonedDateTime.of(1, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC")), dateTimeValue);
			final long elapsedSeconds = duration.getSeconds();
			return Base64.getEncoder().encodeToString(Utilities.getLittleEndianBytes(elapsedSeconds));
		}
	}

	/**
	 * Formats an integer value.
	 *
	 * @param value the value
	 * @return the decimal text
	 */
	private static String formatIntegerValue(final int value) {
		return Integer.toString(value);
	}

	/**
	 * Formats a boolean value.
	 *
	 * @param value the value
	 * @return "True" or "False"
	 */
	private static String formatBooleanValue(final boolean value) {
		return value ? "True" : "False";
	}

	/**
	 * Formats a boolean value, which may be null (e.g. "inherit from parent group").
	 *
	 * @param value the value
	 * @return "True", "False" or "null"
	 */
	private static String formatNullableBooleanValue(final Boolean value) {
		return value == null ? "null" : formatBooleanValue(value);
	}

	/**
	 * Formats a UUID value as base64 text.
	 *
	 * @param uuid the UUID
	 * @return the base64 text
	 */
	private static String formatKdbxUUIDValue(final KdbxUUID uuid) {
		return uuid.toBase64();
	}

	/**
	 * Closes the output stream.
	 *
	 * @throws IOException if closing the stream fails
	 */
	@Override
	public void close() throws IOException {
		if (outputStream != null) {
			outputStream.close();
		}
	}
}
