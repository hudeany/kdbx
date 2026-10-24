package de.soderer.utilities.kdbx;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat3;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat4;
import de.soderer.utilities.kdbx.data.KeyDerivationFunctionInfoAes;
import de.soderer.utilities.kdbx.utilities.HmacOutputStream;
import de.soderer.utilities.kdbx.utilities.TypeHashLengthValueStructure;
import de.soderer.utilities.kdbx.utilities.TypeLengthValueStructure;
import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * Test helper, which creates encrypted KDBX 3.1 and 4.1 files with any XML content.
 * <p>
 * Unlike {@link KdbxWriter}, which always writes valid XML, this builder allows unknown or broken XML nodes and inner header fields,
 * so that the validation paths of {@link KdbxReader} can be reached.
 * <p>
 * XML placeholders:
 * <ul>
 * <li>"{P:text}" is replaced by the base64 value of "text", encrypted with the inner stream cipher, for protected values. The placeholders are encrypted in document order, like KeePass does.</li>
 * <li>"{HEADERHASH}" (KDBX 3 only) is replaced by the base64 SHA-256 hash of the outer header.</li>
 * </ul>
 */
final class KdbxTestFileBuilder {
	private static final Pattern PROTECTED_VALUE_PATTERN = Pattern.compile("\\{P:([^}]*)\\}");

	/** Inner header fields of KDBX 4 */
	static final int INNER_STREAM_ID = 1;
	static final int INNER_STREAM_KEY = 2;
	static final int INNER_BINARY = 3;

	private KdbxTestFileBuilder() {
		// Utility class
	}

	/**
	 * Creates the XML document with the given content of the Meta and Root nodes.
	 */
	static String xml(final String metaContent, final String rootContent) {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><KeePassFile><Meta>" + metaContent + "</Meta><Root>" + rootContent + "</Root></KeePassFile>";
	}

	/**
	 * Formats a time value as stored in KDBX 4 (base64 of the little endian seconds since 0001-01-01 UTC).
	 */
	static String kdbx4Time(final ZonedDateTime time) {
		final long seconds = Duration.between(ZonedDateTime.of(1, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC")), time).getSeconds();
		return Base64.getEncoder().encodeToString(Utilities.getLittleEndianBytes(seconds));
	}

	/**
	 * Creates the inner header of a KDBX 4 file with the given fields (type id, data) and the terminating field.
	 */
	static byte[] innerHeader(final Object... typeIdsAndData) throws Exception {
		final ByteArrayOutputStream innerHeaderStream = new ByteArrayOutputStream();
		for (int i = 0; i < typeIdsAndData.length; i += 2) {
			new TypeLengthValueStructure((Integer) typeIdsAndData[i], (byte[]) typeIdsAndData[i + 1]).write(innerHeaderStream, true);
		}
		new TypeLengthValueStructure(0, new byte[0]).write(innerHeaderStream, true);
		return innerHeaderStream.toByteArray();
	}

	/**
	 * Creates the standard inner header of a KDBX 4 file with ChaCha20 inner encryption and the given attachments (stored with flags byte 0x01).
	 */
	static byte[] standardInnerHeader(final byte[] innerStreamKey, final byte[]... attachments) throws Exception {
		final List<Object> fields = new ArrayList<>(Arrays.asList(INNER_STREAM_ID, Utilities.getLittleEndianBytes(InnerEncryptionAlgorithm.CHACHA20.getId()), INNER_STREAM_KEY, innerStreamKey));
		for (final byte[] attachment : attachments) {
			fields.add(INNER_BINARY);
			fields.add(Utilities.concatArrays(new byte[] { 0x01 }, attachment));
		}
		return innerHeader(fields.toArray());
	}

	/**
	 * Creates a random inner stream key.
	 */
	static byte[] newInnerStreamKey() {
		final byte[] key = new byte[64];
		new java.security.SecureRandom().nextBytes(key);
		return key;
	}

	/**
	 * Creates a KDBX 4.1 file (AES-256, AES-KDF with few rounds, no compression) with the standard inner header.
	 */
	static byte[] buildKdbx4(final String xml, final KdbxCredentials credentials, final byte[]... attachments) throws Exception {
		final byte[] innerStreamKey = newInnerStreamKey();
		return buildKdbx4(xml, credentials, standardInnerHeader(innerStreamKey, attachments), InnerEncryptionAlgorithm.CHACHA20, innerStreamKey);
	}

	/**
	 * Creates a KDBX 4.1 file (AES-256, AES-KDF with few rounds, no compression) with the given inner header.
	 *
	 * @param innerHeader the complete inner header data
	 * @param innerEncryptionAlgorithm the inner stream cipher used for the "{P:...}" placeholders
	 * @param innerStreamKey the key of the inner stream cipher used for the "{P:...}" placeholders
	 */
	static byte[] buildKdbx4(final String xml, final KdbxCredentials credentials, final byte[] innerHeader, final InnerEncryptionAlgorithm innerEncryptionAlgorithm, final byte[] innerStreamKey) throws Exception {
		return buildKdbx4(createHeader4(), xml, credentials, innerHeader, innerEncryptionAlgorithm, innerStreamKey);
	}

	/**
	 * Creates the default header of the KDBX 4 files of this builder (AES-256, AES-KDF with few rounds, no compression).
	 */
	static KdbxHeaderFormat4 createHeader4() {
		return new KdbxHeaderFormat4().withCompressData(false).withKeyDerivationFunctionInfo(new KeyDerivationFunctionInfoAes().withAesTransformRounds(10));
	}

	/**
	 * Creates a KDBX 4 file with the given outer header. The payload is always encrypted with AES-256, so headers with other outer encryption algorithms create unreadable files.
	 */
	static byte[] buildKdbx4(final KdbxHeaderFormat4 header, final String xml, final KdbxCredentials credentials, final byte[] innerHeader, final InnerEncryptionAlgorithm innerEncryptionAlgorithm, final byte[] innerStreamKey) throws Exception {
		final byte[] headerBytes = header.getHeaderBytes();
		final byte[] encryptionKey = header.getEncryptionKey(credentials.createCompositeKeyHash());

		final ByteArrayOutputStream fileStream = new ByteArrayOutputStream();
		fileStream.write(headerBytes);
		fileStream.write(MessageDigest.getInstance("SHA-256").digest(headerBytes));

		final MessageDigest hmacKeyDigest = MessageDigest.getInstance("SHA-512");
		hmacKeyDigest.update(header.getMasterSeed());
		hmacKeyDigest.update(encryptionKey);
		final byte[] hmacKey = hmacKeyDigest.digest(new byte[] { 0x01 });

		final MessageDigest headerHmacKeyDigest = MessageDigest.getInstance("SHA-512");
		headerHmacKeyDigest.update(Utilities.getLittleEndianBytes(0xFFFFFFFF_FFFFFFFFL));
		final Mac headerHmac = Mac.getInstance("HmacSHA256");
		headerHmac.init(new SecretKeySpec(headerHmacKeyDigest.digest(hmacKey), "HmacSHA256"));
		fileStream.write(headerHmac.doFinal(headerBytes));

		final byte[] xmlBytes = replaceProtectedValues(xml, createInnerCipher(innerEncryptionAlgorithm, innerStreamKey)).getBytes(StandardCharsets.UTF_8);
		final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(Utilities.concatArrays(header.getMasterSeed(), encryptionKey));
		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(finalKey, "AES"), new IvParameterSpec(header.getEncryptionIV()));
		final byte[] encryptedPayload = cipher.doFinal(Utilities.concatArrays(innerHeader, xmlBytes));

		try (HmacOutputStream hmacOutputStream = new HmacOutputStream(fileStream, hmacKey)) {
			hmacOutputStream.write(encryptedPayload);
		}
		return fileStream.toByteArray();
	}

	/**
	 * Options for broken KDBX 3 files
	 */
	enum Kdbx3Defect {
		NONE,
		/** The first payload block has index 1 instead of 0 */
		WRONG_BLOCK_INDEX,
		/** The stream start bytes do not match the header */
		WRONG_STREAM_START_BYTES,
		/** The payload is shorter than the stream start bytes */
		SHORT_PAYLOAD
	}

	/**
	 * Creates a KDBX 3.1 file (AES-256, few transform rounds, no compression, Salsa20 inner encryption).
	 */
	static byte[] buildKdbx3(final String xml, final KdbxCredentials credentials, final Kdbx3Defect defect) throws Exception {
		return buildKdbx3(new KdbxHeaderFormat3().withCompressData(false).withTransformRounds(10).withInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.SALSA20), xml, credentials, defect);
	}

	/**
	 * Creates a KDBX 3.1 file with the given outer header. The payload is always encrypted with AES-256, so headers with other outer encryption algorithms create unreadable files.
	 */
	static byte[] buildKdbx3(final KdbxHeaderFormat3 header, final String xml, final KdbxCredentials credentials, final Kdbx3Defect defect) throws Exception {
		final byte[] headerBytes = header.getHeaderBytes();
		final String headerHash = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(headerBytes));
		final String xmlWithHeaderHash = xml.replace("{HEADERHASH}", headerHash);
		final byte[] xmlBytes = replaceProtectedValues(xmlWithHeaderHash, createInnerCipher(InnerEncryptionAlgorithm.SALSA20, header.getInnerEncryptionKeyBytes())).getBytes(StandardCharsets.UTF_8);

		final ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
		if (defect == Kdbx3Defect.SHORT_PAYLOAD) {
			payloadStream.write(new byte[10]);
		} else if (defect == Kdbx3Defect.WRONG_STREAM_START_BYTES) {
			payloadStream.write(new byte[header.getStreamStartBytes().length]);
		} else {
			payloadStream.write(header.getStreamStartBytes());
		}
		if (defect != Kdbx3Defect.SHORT_PAYLOAD) {
			final int firstBlockIndex = defect == Kdbx3Defect.WRONG_BLOCK_INDEX ? 1 : 0;
			TypeHashLengthValueStructure.write(payloadStream, firstBlockIndex, xmlBytes, "SHA-256");
			TypeHashLengthValueStructure.write(payloadStream, firstBlockIndex + 1, null, "SHA-256");
		}

		final byte[] encryptionKey = header.getEncryptionKey(credentials.createCompositeKeyHash());
		final byte[] finalKey = MessageDigest.getInstance("SHA-256").digest(Utilities.concatArrays(header.getMasterSeed(), encryptionKey));
		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(finalKey, "AES"), new IvParameterSpec(header.getEncryptionIV()));
		return Utilities.concatArrays(headerBytes, cipher.doFinal(payloadStream.toByteArray()));
	}

	/**
	 * Creates the inner stream cipher for encryption as defined by KeePass.
	 */
	private static StreamCipher createInnerCipher(final InnerEncryptionAlgorithm innerEncryptionAlgorithm, final byte[] innerStreamKey) throws Exception {
		if (innerEncryptionAlgorithm == InnerEncryptionAlgorithm.SALSA20) {
			final byte[] key = MessageDigest.getInstance("SHA-256").digest(innerStreamKey);
			final StreamCipher cipher = new Salsa20Engine();
			cipher.init(true, new ParametersWithIV(new KeyParameter(key), new byte[] { (byte) 0xE8, 0x30, 0x09, 0x4B, (byte) 0x97, 0x20, 0x5D, 0x2A }));
			return cipher;
		} else if (innerEncryptionAlgorithm == InnerEncryptionAlgorithm.CHACHA20) {
			final byte[] key = MessageDigest.getInstance("SHA-512").digest(innerStreamKey);
			final StreamCipher cipher = new ChaCha7539Engine();
			cipher.init(true, new ParametersWithIV(new KeyParameter(Arrays.copyOfRange(key, 0, 32)), Arrays.copyOfRange(key, 32, 44)));
			return cipher;
		} else {
			return null;
		}
	}

	private static String replaceProtectedValues(final String xml, final StreamCipher innerCipher) {
		final Matcher matcher = PROTECTED_VALUE_PATTERN.matcher(xml);
		final StringBuilder result = new StringBuilder();
		while (matcher.find()) {
			final byte[] plainData = matcher.group(1).getBytes(StandardCharsets.UTF_8);
			final byte[] encryptedData = new byte[plainData.length];
			innerCipher.processBytes(plainData, 0, plainData.length, encryptedData, 0);
			matcher.appendReplacement(result, Matcher.quoteReplacement(Base64.getEncoder().encodeToString(encryptedData)));
		}
		matcher.appendTail(result);
		return result.toString();
	}
}
