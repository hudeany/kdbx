package de.soderer.utilities.kdbx;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import de.soderer.utilities.kdbx.data.KdbxConstants;
import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxInnerHeaderType;
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxOuterHeaderType;
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxVersion;
import de.soderer.utilities.kdbx.data.KdbxConstants.KeyDerivationFunction;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.PayloadBlockType;
import de.soderer.utilities.kdbx.data.KdbxCustomDataItem;
import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxMemoryProtection;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxTimes;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.util.CopyInputStream;
import de.soderer.utilities.kdbx.util.HmacInputStream;
import de.soderer.utilities.kdbx.util.TypeHashLengthValueStructure;
import de.soderer.utilities.kdbx.util.TypeLengthValueStructure;
import de.soderer.utilities.kdbx.util.Utilities;
import de.soderer.utilities.kdbx.util.VariantDictionary;
import de.soderer.utilities.kdbx.util.Version;

public class KdbxReader implements AutoCloseable {
	InputStream inputStream;

	StreamCipher innerEncryptionCipher;

	public KdbxReader(final InputStream inputStream) {
		this.inputStream = inputStream;
	}

	public KdbxDatabase readKdbxDatabase(final char[] password) throws Exception {
		return readKdbxDatabase(new KdbxCredentials(password));
	}

	public KdbxDatabase readKdbxDatabase(final KdbxCredentials credentials) throws Exception {
		try (CopyInputStream copyInputStream = new CopyInputStream(inputStream)) {
			copyInputStream.setCopyOnRead(true);

			int magicNumber;
			try {
				magicNumber = Utilities.readLittleEndianIntFromStream(copyInputStream);
			} catch (final Exception e) {
				throw new Exception("Cannot read kdbx magic number", e);
			}
			if (magicNumber != KdbxConstants.KDBX_MAGICNUMBER) {
				throw new IOException("Data does not include kdbx data (Invalid magic number " + Integer.toHexString(magicNumber) + ")");
			}

			int kdbxVersionId;
			KdbxVersion kdbxVersion;
			try {
				kdbxVersionId = Utilities.readLittleEndianIntFromStream(copyInputStream);
			} catch (final Exception e) {
				throw new Exception("Cannot read kdbx version number", e);
			}
			try {
				kdbxVersion = KdbxVersion.getById(kdbxVersionId);
			} catch (final Exception e) {
				throw new Exception("Invalid kdbx version: " + e.getMessage(), e);
			}
			if (kdbxVersion != KdbxVersion.KEEPASS2) {
				throw new Exception("Unsupported kdbx version: " + kdbxVersion);
			}

			final Version dataFormatVersion;
			try {
				final short minorDataFormatVersion = Utilities.readLittleEndianShortFromStream(copyInputStream);
				final short majorDataFormatVersion = Utilities.readLittleEndianShortFromStream(copyInputStream);
				dataFormatVersion = new Version(majorDataFormatVersion, minorDataFormatVersion, 0);
			} catch (final Exception e) {
				throw new Exception("Cannot read kdbx data format version: " + e.getMessage(), e);
			}

			final Map<KdbxOuterHeaderType, byte[]> outerHeaders = new HashMap<>();
			TypeLengthValueStructure nextStructure;
			while ((nextStructure = TypeLengthValueStructure.read(copyInputStream, dataFormatVersion.getMajorVersionNumber() == 4)).getTypeId() != KdbxOuterHeaderType.END_OF_HEADER.getId()) {
				outerHeaders.put(KdbxOuterHeaderType.getById(nextStructure.getTypeId()), nextStructure.getData());
			}

			final byte[] outerHeadersDataBytes = copyInputStream.getCopiedData();
			copyInputStream.setCopyOnRead(false);

			byte[] decryptedXmlPayloadData = null;
			if (dataFormatVersion.getMajorVersionNumber() == 3) {
				decryptedXmlPayloadData = decryptVersion3(credentials, outerHeaders);
			} else if (dataFormatVersion.getMajorVersionNumber() == 4) {
				decryptedXmlPayloadData = decryptVersion4(credentials, outerHeaders, outerHeadersDataBytes);
			} else {
				throw new Exception("Major kdbx file version " + dataFormatVersion.getMajorVersionNumber() + " is not supported");
			}

			final Document document = Utilities.parseXmlFile(decryptedXmlPayloadData);

			final KdbxDatabase database = new KdbxDatabase();

			final Element rootNode = document.getDocumentElement();
			final NodeList childNodes = rootNode.getChildNodes();
			for (int i = 0; i < childNodes.getLength(); i++) {
				final Node childNode = childNodes.item(i);
				if (childNode.getNodeType() != Node.TEXT_NODE) {
					if ("Meta".equals(childNode.getNodeName())) {
						readKdbxMetaData(dataFormatVersion, database, childNode);
					} else if ("Root".equals(childNode.getNodeName())) {
						readKdbxRoot(dataFormatVersion, database, childNode);
					} else {
						throw new Exception("Unexpected data node name: " + childNode.getNodeName());
					}
				}
			}

			return database;
		}
	}

	private byte[] decryptVersion3(final KdbxCredentials credentials, final Map<KdbxOuterHeaderType, byte[]> outerHeaders) throws Exception {
		final byte[] decryptionKey;
		byte[] decryptedPayload;
		final long transformRounds = Utilities.readLittleEndianValueFromByteArray(outerHeaders.get(KdbxOuterHeaderType.TRANSFORM_ROUNDS));
		final byte[] transformSeed = outerHeaders.get(KdbxOuterHeaderType.TRANSFORM_SEED);
		decryptionKey = deriveKeyByAES(credentials, transformRounds, transformSeed);

		final byte[] encryptedData = Utilities.toByteArray(inputStream);
		byte[] decryptedData;
		try  {
			final byte[] masterSeed = outerHeaders.get(KdbxOuterHeaderType.MASTER_SEED);
			final byte[] transformedKey = Utilities.concatArrays(masterSeed, decryptionKey);
			final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(transformedKey);
			final OuterEncryptionAlgorithm outerEncryptionAlgorithm = OuterEncryptionAlgorithm.getById(outerHeaders.get(KdbxOuterHeaderType.CIPHER_ID));
			if (outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_128 && outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_256) {
				throw new IllegalArgumentException("Cipher " + outerEncryptionAlgorithm + " is not implemented yet");
			}
			final byte[] encryptionIV = outerHeaders.get(KdbxOuterHeaderType.ENCRYPTION_IV);

			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			final SecretKeySpec secretKeySpec = new SecretKeySpec(finalKey, "AES");
			final AlgorithmParameterSpec paramSpec = new IvParameterSpec(encryptionIV);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, paramSpec);
			decryptedData = cipher.doFinal(encryptedData);
		} catch(final BadPaddingException e) {
			throw new Exception("Decryption failed because of bad padding",e);
		} catch(final Exception e) {
			throw new Exception("Decryption failed",e);
		}

		final ByteArrayInputStream decryptedPayloadStream = new ByteArrayInputStream(decryptedData);
		final byte[] expected = outerHeaders.get(KdbxOuterHeaderType.STREAM_START_BYTES);
		final byte[] actual = new byte[expected.length];
		final int readBytes = decryptedPayloadStream.read(actual);
		if (readBytes != expected.length) {
			throw new Exception("Cannot read start bytes from payload: Not enough data left");
		}
		if (!Arrays.equals(expected, actual)) {
			throw new Exception("Bad master key, decryption failed");
		}

		final ByteArrayOutputStream payloadData = new ByteArrayOutputStream();
		TypeHashLengthValueStructure nextTypeHashLengthValueStructure;
		do {
			nextTypeHashLengthValueStructure = TypeHashLengthValueStructure.read(decryptedPayloadStream, "SHA-256");
			if (nextTypeHashLengthValueStructure.getTypeId() == PayloadBlockType.PAYLOAD.getId()) {
				payloadData.write(nextTypeHashLengthValueStructure.getData());
			}
		} while (nextTypeHashLengthValueStructure.getTypeId() != PayloadBlockType.END_OF_PAYLOAD.getId());

		final byte[] flagsBytes = outerHeaders.get(KdbxOuterHeaderType.COMPRESSION_FLAGS);
		final boolean streamIsCompressed = flagsBytes != null && (Utilities.readIntFromLittleEndianBytes(flagsBytes) & 1) == 1;

		final byte[] innerEncryptionAlgorithmIdBytes = outerHeaders.get(KdbxOuterHeaderType.INNER_RANDOM_STREAM_ID);
		if (innerEncryptionAlgorithmIdBytes == null) {
			throw new Exception("Inner header lacks RANDOM_STREAM_ID");
		}
		final InnerEncryptionAlgorithm innerEncryptionAlgorithm = InnerEncryptionAlgorithm.getById(Utilities.readIntFromLittleEndianBytes(innerEncryptionAlgorithmIdBytes));
		final byte[] innerEncryptionKeyBytes = outerHeaders.get(KdbxOuterHeaderType.PROTECTED_STREAM_KEY);
		innerEncryptionCipher = createInnerEncryptionCipher(innerEncryptionAlgorithm, innerEncryptionKeyBytes);

		decryptedPayload = payloadData.toByteArray();
		if (streamIsCompressed) {
			try (final GZIPInputStream gzipIn = new GZIPInputStream(new ByteArrayInputStream(decryptedPayload))) {
				decryptedPayload = Utilities.toByteArray(gzipIn);
			} catch (final IOException e) {
				throw new Exception("GZIP decompression failed", e);
			}
		}
		return decryptedPayload;
	}

	private byte[] decryptVersion4(final KdbxCredentials credentials, final Map<KdbxOuterHeaderType, byte[]> outerHeaders, final byte[] outerHeadersDataBytes) throws Exception {
		final byte[] decryptedPayload;
		final byte[] kdfParamsBytes = outerHeaders.get(KdbxOuterHeaderType.KDF_PARAMETERS);
		final VariantDictionary variantDictionary = VariantDictionary.read(new ByteArrayInputStream(kdfParamsBytes));
		final KeyDerivationFunction keyDerivationFunction = KeyDerivationFunction.getById((byte[]) variantDictionary.get(VariantDictionary.KDF_UUID).getJavaValue());
		final byte[] decryptionKey;
		switch (keyDerivationFunction) {
			case AES_KDBX3:
			case AES_KDBX4:
				final long aesTransformRounds = (Long) variantDictionary.get(VariantDictionary.KDF_AES_ROUNDS).getJavaValue();
				final byte[] aesTransformSeed = (byte[]) variantDictionary.get(VariantDictionary.KDF_AES_SEED).getJavaValue();
				decryptionKey = deriveKeyByAES(credentials, aesTransformRounds, aesTransformSeed);
				break;
			case ARGON2D:
				decryptionKey = createArgon2DerivedPassword(credentials, variantDictionary, Argon2Parameters.ARGON2_d);
				break;
			case ARGON2ID:
				decryptionKey = createArgon2DerivedPassword(credentials, variantDictionary, Argon2Parameters.ARGON2_id);
				break;
			default:
				throw new Exception("Unknown KeyDerivationFunction(KDF): " + keyDerivationFunction);
		}

		final byte[] masterSeed = outerHeaders.get(KdbxOuterHeaderType.MASTER_SEED);
		if (masterSeed.length != 32) {
			throw new IllegalStateException("Master seed should have 32 bytes");
		}

		// SHA-256 Hash verification of headerBytes
		final byte[] expectedSha256 = new byte[32];
		final int readBytesExpectedSha256 = inputStream.read(expectedSha256);
		if (readBytesExpectedSha256 != expectedSha256.length) {
			throw new IllegalStateException("Cannot read header SHA-256 hash bytes");
		}
		final byte[] actualSha256 = MessageDigest.getInstance("SHA-256").digest(outerHeadersDataBytes);
		if (!Arrays.equals(actualSha256, expectedSha256)) {
			throw new RuntimeException("Outer header data corrupted, SHA-256 hashes do not match");
		}

		final byte[] transformedKey = Utilities.concatArrays(masterSeed, decryptionKey);
		final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(transformedKey);
		final OuterEncryptionAlgorithm outerEncryptionAlgorithm = OuterEncryptionAlgorithm.getById(outerHeaders.get(KdbxOuterHeaderType.CIPHER_ID));
		final byte[] encryptionIV = outerHeaders.get(KdbxOuterHeaderType.ENCRYPTION_IV);

		final MessageDigest digest = MessageDigest.getInstance("SHA-512");
		digest.update(masterSeed);
		digest.update(decryptionKey);
		final byte[] hmacKey = digest.digest(new byte[] { 0x01 });

		// HMAC-SHA-256 verification of headerBytes
		final byte[] expectedHeaderHMAC = new byte[32];
		final int readBytesExpectedHeaderHMAC = inputStream.read(expectedHeaderHMAC);
		if (readBytesExpectedHeaderHMAC != expectedSha256.length) {
			throw new IllegalStateException("Cannot read HMAC code bytes");
		}
		final byte[] indexBytes = Utilities.getLittleEndianBytes(0xFFFFFFFF_FFFFFFFFL);
		final MessageDigest headerVerificationKeyDigest = MessageDigest.getInstance("SHA-512");
		headerVerificationKeyDigest.update(indexBytes);
		final byte[] headerVerificationHmacKey = headerVerificationKeyDigest.digest(hmacKey);

		final Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		sha256_HMAC.init(new SecretKeySpec(headerVerificationHmacKey, "HmacSHA256"));
		sha256_HMAC.update(outerHeadersDataBytes, 0, outerHeadersDataBytes.length);
		final byte[] actualHeaderHMAC = sha256_HMAC.doFinal();
		if (!Arrays.equals(actualHeaderHMAC, expectedHeaderHMAC)) {
			throw new RuntimeException("Outer header data corrupted, MAC-SHA-256 hashes do not match: Maybe the credentials for this database are wrong?");
		}

		inputStream = new HmacInputStream(inputStream, hmacKey);

		final Cipher cipher;
		final SecretKeySpec secretKeySpec;
		final AlgorithmParameterSpec paramSpec;
		switch (outerEncryptionAlgorithm) {
			case AES_128:
			case AES_256:
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				secretKeySpec = new SecretKeySpec(finalKey, "AES");
				paramSpec = new IvParameterSpec(encryptionIV);
				break;
			case CHACHA20:
				Security.addProvider(new BouncyCastleProvider());
				cipher = Cipher.getInstance("ChaCha20");
				secretKeySpec = new SecretKeySpec(finalKey, "AES");
				paramSpec = new IvParameterSpec(encryptionIV);
				break;
			case TWOFISH:
				throw new IllegalArgumentException("Cipher " + outerEncryptionAlgorithm + " is not implemented yet");
			default:
				throw new IllegalArgumentException("Unknown cipher " + outerEncryptionAlgorithm);
		}
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, paramSpec);
		inputStream = new CipherInputStream(inputStream, cipher);

		final byte[] flagsBytes = outerHeaders.get(KdbxOuterHeaderType.COMPRESSION_FLAGS);
		final boolean streamIsCompressed = flagsBytes != null && (Utilities.readIntFromLittleEndianBytes(flagsBytes) & 1 ) == 1;

		if (streamIsCompressed) {
			inputStream = new GZIPInputStream(inputStream);
		}

		final Map<KdbxInnerHeaderType, byte[]> innerHeaders = new HashMap<>();
		TypeLengthValueStructure nextInnerHeaderStructure;
		while ((nextInnerHeaderStructure = TypeLengthValueStructure.read(inputStream, true)).getTypeId() != KdbxInnerHeaderType.END_OF_HEADER.getId()) {
			innerHeaders.put(KdbxInnerHeaderType.getById(nextInnerHeaderStructure.getTypeId()), nextInnerHeaderStructure.getData());
		}

		final byte[] innerEncryptionAlgorithmIdBytes = innerHeaders.get(KdbxInnerHeaderType.INNER_RANDOM_STREAM_ID);
		if (innerEncryptionAlgorithmIdBytes == null) {
			throw new Exception("Inner header lacks RANDOM_STREAM_ID");
		}
		final InnerEncryptionAlgorithm innerEncryptionAlgorithm = InnerEncryptionAlgorithm.getById(Utilities.readIntFromLittleEndianBytes(innerEncryptionAlgorithmIdBytes));
		final byte[] innerEncryptionKeyBytes = innerHeaders.get(KdbxInnerHeaderType.INNER_RANDOM_STREAM_KEY);
		innerEncryptionCipher = createInnerEncryptionCipher(innerEncryptionAlgorithm, innerEncryptionKeyBytes);

		decryptedPayload = Utilities.toByteArray(inputStream);
		return decryptedPayload;
	}

	private static byte[] createArgon2DerivedPassword(final KdbxCredentials credentials, final VariantDictionary variantDictionary, final int argon2Type) throws Exception {
		final Argon2Parameters.Builder builder = new Argon2Parameters.Builder(argon2Type);
		builder.withIterations(((Number) variantDictionary.get(VariantDictionary.KDF_ARGON2_ITERATIONS).getJavaValue()).intValue());
		builder.withMemoryAsKB((int) (((Number) variantDictionary.get(VariantDictionary.KDF_ARGON2_MEMORY_IN_BYTES).getJavaValue()).longValue() / 1024));
		builder.withParallelism(((Number) variantDictionary.get(VariantDictionary.KDF_ARGON2_PARALLELISM).getJavaValue()).intValue());
		builder.withSalt((byte[]) variantDictionary.get(VariantDictionary.KDF_ARGON2_SALT ).getJavaValue());
		builder.withVersion(((Number) variantDictionary.get(VariantDictionary.KDF_ARGON2_VERSION).getJavaValue()).intValue());

		final Argon2Parameters parameters = builder.build();
		final Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(parameters);

		final byte[] output = new byte[32];
		generator.generateBytes(credentials.createCompositeKeyHash(), output);
		return output;
	}

	private static byte[] deriveKeyByAES(final KdbxCredentials credentials, final long transformRounds, final byte[] transformSeed) throws Exception {
		final byte[] compositeKeyHash = credentials.createCompositeKeyHash();
		if (compositeKeyHash == null || compositeKeyHash.length != 32) {
			throw new Exception("Cannot derive key");
		}
		final byte[] resultLeft = Utilities.deriveKeyByAES(transformSeed, transformRounds, Arrays.copyOfRange(compositeKeyHash, 0, 16));
		final byte[] resultRight = Utilities.deriveKeyByAES(transformSeed, transformRounds, Arrays.copyOfRange(compositeKeyHash, 16, 32));
		final byte[] transformed = Utilities.concatArrays(resultLeft, resultRight);
		return MessageDigest.getInstance("SHA-256").digest(transformed);
	}

	private StreamCipher createInnerEncryptionCipher(final InnerEncryptionAlgorithm innerEncryptionAlgorithm, final byte[] innerEncryptionKeyBytes) throws Exception {
		switch (innerEncryptionAlgorithm) {
			case SALSA20:
				if (innerEncryptionKeyBytes == null || innerEncryptionKeyBytes.length == 0) {
					throw new Exception("innerEncryptionKeyBytes must not be null or empty");
				} else {
					final byte[] key =  MessageDigest.getInstance("SHA-256").digest(innerEncryptionKeyBytes);
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
				throw new RuntimeException("Unsupported algorith ARC4_VARIANT");
			case NONE:
				throw new RuntimeException("Undefined algorith");
			default:
				// no inner encryption
				return null;
		}
	}

	private String decryptProtectedValue(final String base64CipherText) {
		if (innerEncryptionCipher == null) {
			return base64CipherText;
		} else {
			final byte[] encrypedData = Base64.getDecoder().decode(base64CipherText);
			final byte[] output = new byte[encrypedData.length];
			innerEncryptionCipher.processBytes(encrypedData, 0, encrypedData.length, output, 0);
			return new String(output, StandardCharsets.UTF_8);
		}
	}

	private static void readKdbxMetaData(final Version dataFormatVersion, final KdbxDatabase database, final Node metaNode) throws Exception {
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
					kdbxMeta.setMaintenanceHistoryDays(parseStringValue(childNode));
				} else if ("Color".equals(childNode.getNodeName())) {
					kdbxMeta.setColor(parseStringValue(childNode));
				} else if ("MasterKeyChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setMasterKeyChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("MasterKeyChangeRec".equals(childNode.getNodeName())) {
					kdbxMeta.setMasterKeyChangeRec(parseStringValue(childNode));
				} else if ("MasterKeyChangeForce".equals(childNode.getNodeName())) {
					kdbxMeta.setMasterKeyChangeForce(parseStringValue(childNode));
				} else if ("RecycleBinEnabled".equals(childNode.getNodeName())) {
					kdbxMeta.setRecycleBinEnabled(parseStringValue(childNode));
				} else if ("RecycleBinUUID".equals(childNode.getNodeName())) {
					kdbxMeta.setRecycleBinUUID(parseStringValue(childNode));
				} else if ("RecycleBinChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setRecycleBinChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("EntryTemplatesGroup".equals(childNode.getNodeName())) {
					kdbxMeta.setEntryTemplatesGroup(parseStringValue(childNode));
				} else if ("EntryTemplatesGroupChanged".equals(childNode.getNodeName())) {
					kdbxMeta.setEntryTemplatesGroupChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("HistoryMaxItems".equals(childNode.getNodeName())) {
					kdbxMeta.setHistoryMaxItems(parseStringValue(childNode));
				} else if ("HistoryMaxSize".equals(childNode.getNodeName())) {
					kdbxMeta.setHistoryMaxSize(parseStringValue(childNode));
				} else if ("LastSelectedGroup".equals(childNode.getNodeName())) {
					kdbxMeta.setLastSelectedGroup(parseStringValue(childNode));
				} else if ("LastTopVisibleGroup".equals(childNode.getNodeName())) {
					kdbxMeta.setLastTopVisibleGroup(parseStringValue(childNode));
				} else if ("Binaries".equals(childNode.getNodeName())) {
					kdbxMeta.setBinaries(parseStringValue(childNode));
				} else if ("MemoryProtection".equals(childNode.getNodeName())) {
					kdbxMeta.setMemoryProtection(parseMemoryProtection(childNode));
				} else if ("CustomData".equals(childNode.getNodeName())) {
					kdbxMeta.setCustomData(parseCustomData(dataFormatVersion, childNode));
				} else {
					throw new Exception("Unexpected meta attribute node name: " + childNode.getNodeName());
				}
			}
		}
		database.setMeta(kdbxMeta);
	}

	private static KdbxMemoryProtection parseMemoryProtection(final Node memoryProtectionNode) throws Exception {
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
					throw new Exception("Unexpected meta memoryProtection node name: " + childNode.getNodeName());
				}
			}
		}
		return memoryProtection;
	}

	private static List<KdbxCustomDataItem> parseCustomData(final Version dataFormatVersion, final Node customDataNode) throws Exception {
		final List<KdbxCustomDataItem> customDataItems = new ArrayList<>();
		final NodeList childNodes = customDataNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Item".equals(childNode.getNodeName())) {
					customDataItems.add(parseCustomDataItem(dataFormatVersion, childNode));
				} else {
					throw new Exception("Unexpected customData node name: " + childNode.getNodeName());
				}
			}
		}
		return customDataItems;
	}

	private static KdbxCustomDataItem parseCustomDataItem(final Version dataFormatVersion, final Node customDataItemNode) throws Exception {
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
					throw new Exception("Unexpected customData attribute node name: " + childNode.getNodeName());
				}
			}
		}
		return customDataItem;
	}

	private void readKdbxRoot(final Version dataFormatVersion, final KdbxDatabase database, final Node rootNode) throws Exception {
		final NodeList childNodes = rootNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("Group".equals(childNode.getNodeName())) {
					database.getGroups().add(readKdbxGroup(dataFormatVersion, childNode));
				} else if ("Entry".equals(childNode.getNodeName())) {
					database.getEntries().add(readKdbxEntry(dataFormatVersion, childNode));
				} else if ("DeletedObjects".equals(childNode.getNodeName())) {
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
											throw new Exception("Unexpected root data node name: " + childNode.getNodeName());
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
								throw new Exception("Unexpected deleted object data node name: " + deletedObjectsChildNode.getNodeName());
							}
						}
					}
				} else {
					throw new Exception("Unexpected root data node name: " + childNode.getNodeName());
				}
			}
		}
	}

	private KdbxGroup readKdbxGroup(final Version dataFormatVersion, final Node groupNode) throws Exception {
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
					group.setIsExpanded(parseBooleanValue(childNode));
				} else if ("DefaultAutoTypeSequence".equals(childNode.getNodeName())) {
					group.setDefaultAutoTypeSequence(parseStringValue(childNode));
				} else if ("EnableAutoType".equals(childNode.getNodeName())) {
					group.setEnableAutoType(parseStringValue(childNode));
				} else if ("EnableSearching".equals(childNode.getNodeName())) {
					group.setEnableSearching(parseStringValue(childNode));
				} else if ("LastTopVisibleEntry".equals(childNode.getNodeName())) {
					group.setLastTopVisibleEntry(parseUuidValue(childNode));
				} else if ("Times".equals(childNode.getNodeName())) {
					group.setTimes(readKdbxTimes(dataFormatVersion, childNode));
				} else if ("Group".equals(childNode.getNodeName())) {
					group.getGroups().add(readKdbxGroup(dataFormatVersion, childNode));
				} else if ("Entry".equals(childNode.getNodeName())) {
					group.getEntries().add(readKdbxEntry(dataFormatVersion, childNode));
				} else {
					throw new Exception("Unexpected group data node name: " + childNode.getNodeName());
				}
			}
		}
		return group;
	}

	private static KdbxTimes readKdbxTimes(final Version dataFormatVersion, final Node timesNode) throws Exception {
		final KdbxTimes group = new KdbxTimes();
		final NodeList childNodes = timesNode.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			final Node childNode = childNodes.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				if ("CreationTime".equals(childNode.getNodeName())) {
					group.setCreationTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("LastModificationTime".equals(childNode.getNodeName())) {
					group.setLastModificationTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("LastAccessTime".equals(childNode.getNodeName())) {
					group.setLastAccessTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("ExpiryTime".equals(childNode.getNodeName())) {
					group.setExpiryTime(parseDateTimeValue(dataFormatVersion, childNode));
				} else if ("Expires".equals(childNode.getNodeName())) {
					group.setExpires(parseBooleanValue(childNode));
				} else if ("UsageCount".equals(childNode.getNodeName())) {
					group.setUsageCount(parseIntegerValue(childNode));
				} else if ("LocationChanged".equals(childNode.getNodeName())) {
					group.setLocationChanged(parseDateTimeValue(dataFormatVersion, childNode));
				} else {
					throw new Exception("Unexpected times data node name: " + childNode.getNodeName());
				}
			}
		}
		return group;
	}

	private KdbxEntry readKdbxEntry(final Version dataFormatVersion, final Node entryNode) throws Exception {
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
					parseKeyValue(entry.getItems(), childNode);
				} else if ("AutoType".equals(childNode.getNodeName())) {
					boolean enabled = false;
					String dataTransferObfuscation = null;
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
							} else if ("Association".equals(autoTypeChildNode.getNodeName())) {
								final NodeList associationChildNodes = autoTypeChildNode.getChildNodes();
								for (int k = 0; k < associationChildNodes.getLength(); k++) {
									final Node associationChildNode = associationChildNodes.item(k);
									if (associationChildNode.getNodeType() != Node.TEXT_NODE) {
										if ("Window".equals(associationChildNode.getNodeName())) {
											window = parseStringValue(autoTypeChildNode);
										} else if ("KeystrokeSequence".equals(associationChildNode.getNodeName())) {
											keystrokeSequence = parseStringValue(autoTypeChildNode);
										} else {
											throw new Exception("Unexpected association data node name: " + associationChildNode.getNodeName());
										}
									}
								}


							} else {
								throw new Exception("Unexpected autotype data node name: " + autoTypeChildNode.getNodeName());
							}
						}
					}
					entry.setAutoType(enabled, dataTransferObfuscation, window, keystrokeSequence);
				} else if ("History".equals(childNode.getNodeName())) {
					final NodeList historyChildNodes = childNode.getChildNodes();
					for (int j = 0; j < historyChildNodes.getLength(); j++) {
						final Node historyChildNode = historyChildNodes.item(j);
						if (historyChildNode.getNodeType() != Node.TEXT_NODE) {
							if ("Entry".equals(historyChildNode.getNodeName())) {
								entry.getHistory().add(readKdbxEntry(dataFormatVersion, historyChildNode));
							} else {
								throw new Exception("Unexpected history entry data node name: " + historyChildNode.getNodeName());
							}
						}
					}
				} else {
					throw new Exception("Unexpected entry data node name: " + childNode.getNodeName());
				}
			}
		}
		return entry;
	}

	public static String parseStringValue(final Node stringValueNode) {
		if (stringValueNode.getNodeValue() != null) {
			return stringValueNode.getNodeValue();
		} else if (stringValueNode.getFirstChild() != null) {
			return parseStringValue(stringValueNode.getFirstChild());
		} else {
			return null;
		}
	}

	public void parseKeyValue(final Map<String, Object> items, final Node keyValueNode) throws Exception {
		String key = null;
		String value = null;
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
					if (isProtected && value != null) {
						value = decryptProtectedValue(value);
					}
				} else {
					throw new Exception("Unexpected key value data node name: " + childNode.getNodeName());
				}
			}
		}
		if (key == null) {
			throw new Exception("Invalid key value data node: Missing key");
		} else {
			items.put(key, value);
		}
	}

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

	private static boolean parseBooleanValue(final Node node) {
		return "True".equals(parseStringValue(node));
	}

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

	private static KdbxUUID parseUuidValue(final Node node) {
		return KdbxUUID.fromBase64(parseStringValue(node));
	}

	@Override
	public void close() throws Exception {
		if (inputStream != null) {
			inputStream.close();
		}
	}
}