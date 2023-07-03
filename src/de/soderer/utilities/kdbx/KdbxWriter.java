package de.soderer.utilities.kdbx;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.zip.GZIPOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
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
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import de.soderer.utilities.kdbx.data.KdbxBinary;
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
import de.soderer.utilities.kdbx.data.KdbxEntryBinary;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxMemoryProtection;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxStorageSettings;
import de.soderer.utilities.kdbx.data.KdbxStorageSettingsFormat4;
import de.soderer.utilities.kdbx.data.KdbxTimes;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.util.HmacOutputStream;
import de.soderer.utilities.kdbx.util.TypeHashLengthValueStructure;
import de.soderer.utilities.kdbx.util.TypeLengthValueStructure;
import de.soderer.utilities.kdbx.util.Utilities;
import de.soderer.utilities.kdbx.util.VariantDictionary;
import de.soderer.utilities.kdbx.util.VariantDictionaryEntry;
import de.soderer.utilities.kdbx.util.Version;

/**
 * Binary attachments
 * The same data should not be stored multiple times.
 * Dataversion <= 3.1 --> stored in KdbxMeta binaries
 * Dataversion >= 4.0 --> stored in KdbxInnerHeaderType.BINARY_ATTACHMENT
 */

// TODO write DeletedObjects
public class KdbxWriter implements AutoCloseable {
	private final OutputStream outputStream;

	private Set<String> additionalKeyNamesToEncrypt = null;

	public KdbxWriter(final OutputStream outputStream) {
		this.outputStream = outputStream;
	}

	public KdbxWriter setAdditionalKeyNamesToEncrypt(final Set<String>  additionalKeyNamesToEncrypt) {
		this.additionalKeyNamesToEncrypt = additionalKeyNamesToEncrypt;
		return this;
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final char[] password) throws Exception {
		writeKdbxDatabase(database, null, new KdbxCredentials(password));
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final KdbxStorageSettings storageSettings, final char[] password) throws Exception {
		writeKdbxDatabase(database, storageSettings, new KdbxCredentials(password));
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final KdbxCredentials credentials) throws Exception {
		writeKdbxDatabase(database, null, credentials);
	}

	public void writeKdbxDatabase(final KdbxDatabase database, KdbxStorageSettings storageSettings, final KdbxCredentials credentials) throws Exception {
		database.validate();

		if (storageSettings == null) {
			storageSettings = new KdbxStorageSettingsFormat4();
		}
		if (storageSettings.getOuterEncryptionAlgorithm() == null) {
			storageSettings.setOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.AES_256);
		}
		if (storageSettings.getInnerEncryptionAlgorithm() == null) {
			storageSettings.setInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.CHACHA20);
		}

		final Map<KdbxOuterHeaderType, byte[]> outerHeaders = new LinkedHashMap<>();
		outerHeaders.put(KdbxOuterHeaderType.CIPHER_ID, storageSettings.getOuterEncryptionAlgorithm().getId());
		outerHeaders.put(KdbxOuterHeaderType.COMPRESSION_FLAGS, Utilities.getLittleEndianBytes(storageSettings.isCompressData() ? 1 : 0));

		final byte[] innerEncryptionKeyBytes = new byte[32];
		new SecureRandom().nextBytes(innerEncryptionKeyBytes);
		final StreamCipher innerEncryptionCipher = createInnerEncryptionCipher(storageSettings.getInnerEncryptionAlgorithm(), innerEncryptionKeyBytes);
		final Map<KdbxInnerHeaderType, byte[]> innerHeaders;
		if (storageSettings.getDataFormatVersion().getMajorVersionNumber() < 4) {
			outerHeaders.put(KdbxOuterHeaderType.INNER_RANDOM_STREAM_ID, Utilities.getLittleEndianBytes(storageSettings.getInnerEncryptionAlgorithm().getId()));
			outerHeaders.put(KdbxOuterHeaderType.PROTECTED_STREAM_KEY, innerEncryptionKeyBytes);
			innerHeaders = null;
		} else {
			innerHeaders = new LinkedHashMap<>();
			innerHeaders.put(KdbxInnerHeaderType.INNER_RANDOM_STREAM_ID, Utilities.getLittleEndianBytes(storageSettings.getInnerEncryptionAlgorithm().getId()));
			innerHeaders.put(KdbxInnerHeaderType.INNER_RANDOM_STREAM_KEY, innerEncryptionKeyBytes);
		}

		if (storageSettings.getDataFormatVersion().getMajorVersionNumber() < 4) {
			writeEncryptedDataVersion3(storageSettings.getDataFormatVersion(), outputStream, outerHeaders, credentials, database, storageSettings, innerEncryptionCipher);
		} else {
			writeEncryptedDataVersion4(storageSettings.getDataFormatVersion(), outputStream, outerHeaders, innerHeaders, credentials, database, storageSettings, innerEncryptionCipher);
		}
	}

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
			writeBinariesToMeta(metaNode, database.getBinaryAttachments());
		}
		return document;
	}

	private void writeEncryptedDataVersion3(final Version dataFormatVersion, final OutputStream dataOutputStream, final Map<KdbxOuterHeaderType, byte[]> outerHeaders, final KdbxCredentials credentials, final KdbxDatabase database, final KdbxStorageSettings storageSettings, final StreamCipher innerEncryptionCipher) throws Exception {
		final ByteArrayOutputStream outerHeaderBufferStream = new ByteArrayOutputStream();

		outerHeaderBufferStream.write(Utilities.getLittleEndianBytes(KdbxConstants.KDBX_MAGICNUMBER));
		outerHeaderBufferStream.write(Utilities.getLittleEndianBytes(KdbxVersion.KEEPASS2.getVersionId()));
		outerHeaderBufferStream.write(Utilities.getLittleEndianBytes((short) dataFormatVersion.getMinorVersionNumber()));
		outerHeaderBufferStream.write(Utilities.getLittleEndianBytes((short) dataFormatVersion.getMajorVersionNumber()));

		if (!outerHeaders.containsKey(KdbxOuterHeaderType.MASTER_SEED)) {
			final byte[] masterSeed = new byte[32];
			new SecureRandom().nextBytes(masterSeed);
			outerHeaders.put(KdbxOuterHeaderType.MASTER_SEED, masterSeed);
		}
		if (!outerHeaders.containsKey(KdbxOuterHeaderType.TRANSFORM_SEED)) {
			final byte[] transformSeed = new byte[32];
			new SecureRandom().nextBytes(transformSeed);
			outerHeaders.put(KdbxOuterHeaderType.TRANSFORM_SEED, transformSeed);
		}
		if (!outerHeaders.containsKey(KdbxOuterHeaderType.TRANSFORM_ROUNDS)) {
			final long transformRounds = 6000;
			outerHeaders.put(KdbxOuterHeaderType.TRANSFORM_ROUNDS, Utilities.getLittleEndianBytes(transformRounds));
		}
		if (!outerHeaders.containsKey(KdbxOuterHeaderType.ENCRYPTION_IV)) {
			final OuterEncryptionAlgorithm outerEncryptionAlgorithm = OuterEncryptionAlgorithm.getById(outerHeaders.get(KdbxOuterHeaderType.CIPHER_ID));
			if (outerEncryptionAlgorithm == OuterEncryptionAlgorithm.CHACHA20) {
				final byte[] initialVectorBytes = new byte[12];
				new SecureRandom().nextBytes(initialVectorBytes);
				outerHeaders.put(KdbxOuterHeaderType.ENCRYPTION_IV, initialVectorBytes);
			} else {
				final byte[] initialVectorBytes = new byte[16];
				new SecureRandom().nextBytes(initialVectorBytes);
				outerHeaders.put(KdbxOuterHeaderType.ENCRYPTION_IV, initialVectorBytes);
			}
		}
		if (!outerHeaders.containsKey(KdbxOuterHeaderType.STREAM_START_BYTES)) {
			final byte[] streamStartBytes = new byte[32];
			new SecureRandom().nextBytes(streamStartBytes);
			outerHeaders.put(KdbxOuterHeaderType.STREAM_START_BYTES, streamStartBytes);
		}
		if (!outerHeaders.containsKey(KdbxOuterHeaderType.INNER_RANDOM_STREAM_ID)) {
			outerHeaders.put(KdbxOuterHeaderType.INNER_RANDOM_STREAM_ID, Utilities.getLittleEndianBytes(InnerEncryptionAlgorithm.SALSA20.getId()));
		}

		for (final Entry<KdbxOuterHeaderType, byte[]> outerHeader : outerHeaders.entrySet().stream().sorted(Map.Entry.comparingByKey()).collect(Collectors.toList())) {
			new TypeLengthValueStructure(outerHeader.getKey().getId(), outerHeader.getValue()).write(outerHeaderBufferStream, false);
		}
		new TypeLengthValueStructure(KdbxOuterHeaderType.END_OF_HEADER.getId(), new byte[] {0x0D, 0x0A, 0x0D, 0x0A}).write(outerHeaderBufferStream, false);
		final byte[] outerHeadersDataBytes = outerHeaderBufferStream.toByteArray();
		dataOutputStream.write(outerHeadersDataBytes);

		final byte[] sha256Hash = MessageDigest.getInstance("SHA-256").digest(outerHeadersDataBytes);
		database.getMeta().setHeaderHash(Base64.getEncoder().encodeToString(sha256Hash));

		final Document document = createXmlDocument(database, storageSettings.getDataFormatVersion(), innerEncryptionCipher);

		final ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
		payloadStream.write(outerHeaders.get(KdbxOuterHeaderType.STREAM_START_BYTES));

		byte[] decryptedPayload = convertXML2ByteArray(document, StandardCharsets.UTF_8);

		final byte[] compressStreamFlagsBytes = outerHeaders.get(KdbxOuterHeaderType.COMPRESSION_FLAGS);
		final boolean compressStream = compressStreamFlagsBytes != null && (Utilities.readIntFromLittleEndianBytes(compressStreamFlagsBytes) & 1) == 1;
		if (compressStream) {
			decryptedPayload = Utilities.gzip(decryptedPayload);
		}
		TypeHashLengthValueStructure.write(payloadStream, PayloadBlockType.PAYLOAD.getId(), decryptedPayload, "SHA-256");
		TypeHashLengthValueStructure.write(payloadStream, PayloadBlockType.END_OF_PAYLOAD.getId(), null, "SHA-256");

		final long transformRounds = Utilities.readLittleEndianValueFromByteArray(outerHeaders.get(KdbxOuterHeaderType.TRANSFORM_ROUNDS));
		final byte[] transformSeed = outerHeaders.get(KdbxOuterHeaderType.TRANSFORM_SEED);
		final byte[] encryptionKey = deriveKeyByAES(credentials, transformRounds, transformSeed);

		byte[] encryptedData;
		try  {
			final byte[] masterSeed = outerHeaders.get(KdbxOuterHeaderType.MASTER_SEED);
			final byte[] transformedKey = Utilities.concatArrays(masterSeed, encryptionKey);
			final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(transformedKey);
			final OuterEncryptionAlgorithm outerEncryptionAlgorithm = OuterEncryptionAlgorithm.getById(outerHeaders.get(KdbxOuterHeaderType.CIPHER_ID));
			if (outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_128 && outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_256) {
				throw new IllegalArgumentException("Cipher " + outerEncryptionAlgorithm + " is not implemented yet");
			}
			final byte[] encryptionIV = outerHeaders.get(KdbxOuterHeaderType.ENCRYPTION_IV);

			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			final SecretKeySpec secretKeySpec = new SecretKeySpec(finalKey, "AES");
			final AlgorithmParameterSpec paramSpec = new IvParameterSpec(encryptionIV);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);
			encryptedData = cipher.doFinal(payloadStream.toByteArray());
		} catch(final BadPaddingException e) {
			throw new Exception("Decryption failed because of bad padding",e);
		} catch(final Exception e) {
			throw new Exception("Decryption failed",e);
		}

		dataOutputStream.write(encryptedData);
		dataOutputStream.flush();
		dataOutputStream.close();
	}

	private void writeEncryptedDataVersion4(final Version dataFormatVersion, OutputStream dataOutputStream, final Map<KdbxOuterHeaderType, byte[]> outerHeaders, final Map<KdbxInnerHeaderType, byte[]> innerHeaders, final KdbxCredentials credentials, final KdbxDatabase database, final KdbxStorageSettings storageSettings, final StreamCipher innerEncryptionCipher) throws Exception {
		final ByteArrayOutputStream outerHeaderBufferStream = new ByteArrayOutputStream();

		outerHeaderBufferStream.write(Utilities.getLittleEndianBytes(KdbxConstants.KDBX_MAGICNUMBER));
		outerHeaderBufferStream.write(Utilities.getLittleEndianBytes(KdbxVersion.KEEPASS2.getVersionId()));
		outerHeaderBufferStream.write(Utilities.getLittleEndianBytes((short) dataFormatVersion.getMinorVersionNumber()));
		outerHeaderBufferStream.write(Utilities.getLittleEndianBytes((short) dataFormatVersion.getMajorVersionNumber()));

		if (!outerHeaders.containsKey(KdbxOuterHeaderType.MASTER_SEED)) {
			final byte[] masterSeed = new byte[32];
			new SecureRandom().nextBytes(masterSeed);
			outerHeaders.put(KdbxOuterHeaderType.MASTER_SEED, masterSeed);
		}
		if (!outerHeaders.containsKey(KdbxOuterHeaderType.KDF_PARAMETERS)) {
			final VariantDictionary variantDictionary = new VariantDictionary();
			variantDictionary.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.ARGON2D.getId());
			variantDictionary.put(VariantDictionary.KDF_ARGON2_VERSION, VariantDictionaryEntry.Type.UINT_32, 19);
			variantDictionary.put(VariantDictionary.KDF_ARGON2_ITERATIONS, VariantDictionaryEntry.Type.UINT_64, (long) 2);
			variantDictionary.put(VariantDictionary.KDF_ARGON2_MEMORY_IN_BYTES, VariantDictionaryEntry.Type.UINT_64, (long) 65536 * 1024);
			variantDictionary.put(VariantDictionary.KDF_ARGON2_PARALLELISM, VariantDictionaryEntry.Type.UINT_32, 2);
			final byte[] saltBytes = new byte[32];
			new SecureRandom().nextBytes(saltBytes);
			variantDictionary.put(VariantDictionary.KDF_ARGON2_SALT, VariantDictionaryEntry.Type.BYTE_ARRAY, saltBytes);
			final ByteArrayOutputStream bufferStream = new ByteArrayOutputStream();
			variantDictionary.write(bufferStream);
			outerHeaders.put(KdbxOuterHeaderType.KDF_PARAMETERS, bufferStream.toByteArray());
		}
		if (!outerHeaders.containsKey(KdbxOuterHeaderType.ENCRYPTION_IV)) {
			final OuterEncryptionAlgorithm outerEncryptionAlgorithm = OuterEncryptionAlgorithm.getById(outerHeaders.get(KdbxOuterHeaderType.CIPHER_ID));
			if (outerEncryptionAlgorithm == OuterEncryptionAlgorithm.CHACHA20) {
				final byte[] initialVectorBytes = new byte[12];
				new SecureRandom().nextBytes(initialVectorBytes);
				outerHeaders.put(KdbxOuterHeaderType.ENCRYPTION_IV, initialVectorBytes);
			} else {
				final byte[] initialVectorBytes = new byte[16];
				new SecureRandom().nextBytes(initialVectorBytes);
				outerHeaders.put(KdbxOuterHeaderType.ENCRYPTION_IV, initialVectorBytes);
			}
		}

		for (final Entry<KdbxOuterHeaderType, byte[]> outerHeader : outerHeaders.entrySet()) {
			new TypeLengthValueStructure(outerHeader.getKey().getId(), outerHeader.getValue()).write(outerHeaderBufferStream, true);
		}
		new TypeLengthValueStructure(KdbxOuterHeaderType.END_OF_HEADER.getId(), new byte[] {0x0D, 0x0A, 0x0D, 0x0A}).write(outerHeaderBufferStream, true);
		final byte[] outerHeadersDataBytes = outerHeaderBufferStream.toByteArray();
		dataOutputStream.write(outerHeadersDataBytes);

		final byte[] sha256Hash = MessageDigest.getInstance("SHA-256").digest(outerHeadersDataBytes);
		dataOutputStream.write(sha256Hash);

		final byte[] kdfParamsBytes = outerHeaders.get(KdbxOuterHeaderType.KDF_PARAMETERS);
		final VariantDictionary variantDictionary = VariantDictionary.read(new ByteArrayInputStream(kdfParamsBytes));
		final KeyDerivationFunction keyDerivationFunction = KeyDerivationFunction.getById((byte[]) variantDictionary.get(VariantDictionary.KDF_UUID).getJavaValue());
		final byte[] encryptionKey;
		switch (keyDerivationFunction) {
			case AES_KDBX3:
			case AES_KDBX4:
				final long aesTransformRounds = (Long) variantDictionary.get(VariantDictionary.KDF_AES_ROUNDS).getJavaValue();
				final byte[] aesTransformSeed = (byte[]) variantDictionary.get(VariantDictionary.KDF_AES_SEED).getJavaValue();
				encryptionKey = deriveKeyByAES(credentials, aesTransformRounds, aesTransformSeed);
				break;
			case ARGON2D:
				encryptionKey = createArgon2DerivedPassword(credentials, variantDictionary, Argon2Parameters.ARGON2_d);
				break;
			case ARGON2ID:
				encryptionKey = createArgon2DerivedPassword(credentials, variantDictionary, Argon2Parameters.ARGON2_id);
				break;
			default:
				throw new Exception("Unknown KeyDerivationFunction(KDF): " + keyDerivationFunction);
		}

		final byte[] transformedKey = Utilities.concatArrays(outerHeaders.get(KdbxOuterHeaderType.MASTER_SEED), encryptionKey);
		final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(transformedKey);
		final OuterEncryptionAlgorithm outerEncryptionAlgorithm = OuterEncryptionAlgorithm.getById(outerHeaders.get(KdbxOuterHeaderType.CIPHER_ID));
		final byte[] encryptionIV = outerHeaders.get(KdbxOuterHeaderType.ENCRYPTION_IV);

		final MessageDigest digest = MessageDigest.getInstance("SHA-512");
		digest.update(outerHeaders.get(KdbxOuterHeaderType.MASTER_SEED));
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

		dataOutputStream = new HmacOutputStream(dataOutputStream, hmacKey);

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
				secretKeySpec = new SecretKeySpec(finalKey, "ChaCha20");
				paramSpec = new IvParameterSpec(encryptionIV);
				break;
			case TWOFISH:
				throw new IllegalArgumentException("Cipher " + outerEncryptionAlgorithm + " is not implemented yet");
			default:
				throw new IllegalArgumentException("Unknown cipher " + outerEncryptionAlgorithm);
		}
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);
		dataOutputStream = new CipherOutputStream(dataOutputStream, cipher);

		final byte[] compressStreamFlagsBytes = outerHeaders.get(KdbxOuterHeaderType.COMPRESSION_FLAGS);
		final boolean compressStream = compressStreamFlagsBytes != null && (Utilities.readIntFromLittleEndianBytes(compressStreamFlagsBytes) & 1) == 1;
		if (compressStream) {
			dataOutputStream = new GZIPOutputStream(dataOutputStream);
		}

		new TypeLengthValueStructure(KdbxInnerHeaderType.INNER_RANDOM_STREAM_ID.getId(), innerHeaders.get(KdbxInnerHeaderType.INNER_RANDOM_STREAM_ID)).write(dataOutputStream, true);
		new TypeLengthValueStructure(KdbxInnerHeaderType.INNER_RANDOM_STREAM_KEY.getId(), innerHeaders.get(KdbxInnerHeaderType.INNER_RANDOM_STREAM_KEY)).write(dataOutputStream, true);
		for (final KdbxBinary binaryAttachment : database.getBinaryAttachments()) {
			new TypeLengthValueStructure(KdbxInnerHeaderType.BINARY_ATTACHMENT.getId(), binaryAttachment.getData()).write(dataOutputStream, true);
		}
		new TypeLengthValueStructure(KdbxInnerHeaderType.END_OF_HEADER.getId(), new byte[0]).write(dataOutputStream, true);

		final Document document = createXmlDocument(database, storageSettings.getDataFormatVersion(), innerEncryptionCipher);

		dataOutputStream.write(convertXML2ByteArray(document, StandardCharsets.UTF_8));
		dataOutputStream.flush();
		dataOutputStream.close();
	}

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

	private Node writeMetaNode(final Version dataFormatVersion, final Node xmlDocumentRootNode, final KdbxMeta meta) {
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
		writeCustomIcons(metaNode, meta.getCustomIcons());
		writeCustomData(dataFormatVersion, metaNode, meta.getCustomData());
		return metaNode;
	}

	private void writeCustomIcons(final Node metaNode, final Map<KdbxUUID, byte[]> customIcons) {
		final Node customIconsNode = Utilities.appendNode(metaNode, "CustomIcons");
		for (final Entry<KdbxUUID, byte[]> customIcon : customIcons.entrySet()) {
			final Node iconNode = Utilities.appendNode(customIconsNode, "Icon");
			Utilities.appendTextValueNode(iconNode, "UUID", formatKdbxUUIDValue(customIcon.getKey()));
			Utilities.appendTextValueNode(iconNode, "Data", Base64.getEncoder().encodeToString(customIcon.getValue()));
		}
	}

	private void writeMemoryProtectionNode(final Node metaNode, final KdbxMemoryProtection memoryProtection) {
		final Node memoryProtectionNode = Utilities.appendNode(metaNode, "MemoryProtection");
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectTitle", formatBooleanValue(memoryProtection.isProtectTitle()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectUserName", formatBooleanValue(memoryProtection.isProtectUserName()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectPassword", formatBooleanValue(memoryProtection.isProtectPassword()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectURL", formatBooleanValue(memoryProtection.isProtectURL()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectNotes", formatBooleanValue(memoryProtection.isProtectNotes()));
	}

	private void writeRootNode(final StreamCipher innerEncryptionCipher, final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node xmlDocumentRootNode, final KdbxDatabase database) {
		final Node rootNode = Utilities.appendNode(xmlDocumentRootNode, "Root");
		for (final KdbxGroup group : database.getGroups()) {
			writeGroupNode(innerEncryptionCipher, keyNamesToEncrypt, dataFormatVersion, rootNode, group);
		}
		for (final KdbxEntry entry : database.getEntries()) {
			writeEntryNode(innerEncryptionCipher, keyNamesToEncrypt, dataFormatVersion, rootNode, entry);
		}
	}

	private void writeBinariesToMeta(final Node metaNode, final List<KdbxBinary> binaryAttachments) throws Exception {
		final Node binariesNode = Utilities.appendNode(metaNode, "Binaries");
		for (final KdbxBinary binaryAttachment : binaryAttachments) {
			final Node binaryNode = Utilities.appendNode(binariesNode, "Binary");
			Utilities.appendTextValueNode(binaryNode, "ID", formatIntegerValue(binaryAttachment.getId()));
			Utilities.appendTextValueNode(binaryNode, "Compressed", formatBooleanValue(binaryAttachment.isCompressed()));
			byte[] valueBytes = binaryAttachment.getData();
			if (binaryAttachment.isCompressed()) {
				valueBytes = Utilities.gzip(valueBytes);
			}
			final String valueString = Base64.getEncoder().encodeToString(valueBytes);
			binaryNode.appendChild(binaryNode.getOwnerDocument().createTextNode(valueString));
		}
	}

	private void writeGroupNode(final StreamCipher innerEncryptionCipher, final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node baseNode, final KdbxGroup group) {
		final Node groupNode = Utilities.appendNode(baseNode, "Group");
		Utilities.appendTextValueNode(groupNode, "UUID", formatKdbxUUIDValue(group.getUuid()));
		Utilities.appendTextValueNode(groupNode, "Name", group.getName());
		Utilities.appendTextValueNode(groupNode, "Notes", group.getNotes());
		Utilities.appendTextValueNode(groupNode, "IconID", formatIntegerValue(group.getIconID()));
		Utilities.appendTextValueNode(groupNode, "IsExpanded", formatBooleanValue(group.isExpanded()));
		Utilities.appendTextValueNode(groupNode, "DefaultAutoTypeSequence", group.getDefaultAutoTypeSequence());
		Utilities.appendTextValueNode(groupNode, "EnableAutoType", formatBooleanValue(group.isEnableAutoType()));
		Utilities.appendTextValueNode(groupNode, "EnableSearching", formatBooleanValue(group.isEnableSearching()));
		Utilities.appendTextValueNode(groupNode, "LastTopVisibleEntry", formatKdbxUUIDValue(group.getLastTopVisibleEntry()));

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

	private void writeCustomData(final Version dataFormatVersion, final Node baseNode, final List<KdbxCustomDataItem> customData) {
		final Node customDataNode = Utilities.appendNode(baseNode, "CustomData");
		for (final KdbxCustomDataItem customDataItem : customData) {
			final Node customDataItemNode = Utilities.appendNode(customDataNode, "Item");
			Utilities.appendTextValueNode(customDataItemNode, "Key", customDataItem.getKey());
			Utilities.appendTextValueNode(customDataItemNode, "Value", customDataItem.getValue());
			Utilities.appendTextValueNode(customDataItemNode, "LastModificationTime", formatDateTimeValue(dataFormatVersion, customDataItem.getLastModificationTime()));
		}
	}

	private void writeEntryNode(final StreamCipher innerEncryptionCipher, final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node baseNode, final KdbxEntry entry) {
		final Node entryNode = Utilities.appendNode(baseNode, "Entry");
		Utilities.appendTextValueNode(entryNode, "UUID", formatKdbxUUIDValue(entry.getUuid()));
		Utilities.appendTextValueNode(entryNode, "IconID", formatIntegerValue(entry.getIconID()));
		Utilities.appendTextValueNode(entryNode, "ForegroundColor", entry.getForegroundColor());
		Utilities.appendTextValueNode(entryNode, "BackgroundColor", entry.getBackgroundColor());
		Utilities.appendTextValueNode(entryNode, "OverrideURL", entry.getOverrideURL());
		Utilities.appendTextValueNode(entryNode, "Tags", entry.getTags());

		writeTimes(dataFormatVersion, entryNode, entry.getTimes());

		for (final Entry<String, Object> itemEntry : entry.getItems().entrySet()) {
			final Node itemNode = Utilities.appendNode(entryNode, "String");
			Utilities.appendTextValueNode(itemNode, "Key", itemEntry.getKey());
			if (keyNamesToEncrypt.contains(itemEntry.getKey())) {
				String value = (String) itemEntry.getValue();
				if (Utilities.isNotBlank(value)) {
					value = encryptProtectedValue(innerEncryptionCipher, value);
				}
				final Node valueNode = Utilities.appendTextValueNode(itemNode, "Value", value);
				Utilities.appendAttribute((Element) valueNode, "Protected", "True");
			} else {
				Utilities.appendTextValueNode(itemNode, "Value", (String) itemEntry.getValue());
			}
		}

		for (final KdbxEntryBinary entryBinary : entry.getBinaries()) {
			// TODO
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

	private String encryptProtectedValue(final StreamCipher innerEncryptionCipher, final String value) {
		if (innerEncryptionCipher == null) {
			return value;
		} else {
			final byte[] data = value.getBytes(StandardCharsets.UTF_8);
			final byte[] output = new byte[data.length];
			innerEncryptionCipher.processBytes(data, 0, data.length, output, 0);
			return Base64.getEncoder().encodeToString(output);
		}
	}

	private void writeTimes(final Version dataFormatVersion, final Node baseNode, final KdbxTimes times) {
		final Node timesNode = Utilities.appendNode(baseNode, "Times");
		Utilities.appendTextValueNode(timesNode, "LastModificationTime", formatDateTimeValue(dataFormatVersion, times.getLastModificationTime()));
		Utilities.appendTextValueNode(timesNode, "CreationTime", formatDateTimeValue(dataFormatVersion, times.getCreationTime()));
		Utilities.appendTextValueNode(timesNode, "LastAccessTime", formatDateTimeValue(dataFormatVersion, times.getLastAccessTime()));
		Utilities.appendTextValueNode(timesNode, "ExpiryTime", formatDateTimeValue(dataFormatVersion, times.getExpiryTime()));
		Utilities.appendTextValueNode(timesNode, "Expires", formatBooleanValue(times.isExpires()));
		Utilities.appendTextValueNode(timesNode, "UsageCount", formatIntegerValue(times.getUsageCount()));
		Utilities.appendTextValueNode(timesNode, "LocationChanged", formatDateTimeValue(dataFormatVersion, times.getLocationChanged()));
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

	private String formatDateTimeValue(final Version dataFormatVersion, final ZonedDateTime dateTimeValue) {
		if (dateTimeValue == null ) {
			return "";
		} else if (dataFormatVersion.getMajorVersionNumber() < 4) {
			return DateTimeFormatter.ISO_DATE_TIME.format(dateTimeValue);
		} else {
			final Duration duration = Duration.between(ZonedDateTime.of(1, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC")), dateTimeValue);
			final long elapsedSeconds = duration.getSeconds();
			return Base64.getEncoder().encodeToString(Utilities.getLittleEndianBytes(elapsedSeconds));
		}
	}

	private String formatIntegerValue(final int value) {
		return Integer.toString(value);
	}

	private String formatBooleanValue(final boolean value) {
		return value ? "True" : "False";
	}

	private String formatKdbxUUIDValue(final KdbxUUID uuid) {
		return uuid.toBase64();
	}

	@Override
	public void close() throws Exception {
		if (outputStream != null) {
			outputStream.close();
		}
	}
}
