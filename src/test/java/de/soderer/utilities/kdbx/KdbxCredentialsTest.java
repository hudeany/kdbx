package de.soderer.utilities.kdbx;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * Tests of the composite key of {@link KdbxCredentials} for all key file formats supported by KeePass.
 * The expected values are computed as defined by KeePass: SHA-256 over the concatenation of SHA-256(password) and the key file key.
 */
@SuppressWarnings("static-method")
public class KdbxCredentialsTest {
	private static final char[] PASSWORD = "P\u00e4ssword".toCharArray();
	private static final byte[] KEY = new byte[32];
	static {
		for (int i = 0; i < KEY.length; i++) {
			KEY[i] = (byte) (i * 7);
		}
	}

	private static byte[] sha256(final byte[] data) throws Exception {
		return MessageDigest.getInstance("SHA-256").digest(data);
	}

	private static byte[] expectedCompositeKey(final char[] password, final byte[] keyFileKey) throws Exception {
		byte[] concatenated = new byte[0];
		if (password != null) {
			concatenated = Utilities.concatArrays(concatenated, sha256(new String(password).getBytes(StandardCharsets.UTF_8)));
		}
		if (keyFileKey != null) {
			concatenated = Utilities.concatArrays(concatenated, keyFileKey);
		}
		return sha256(concatenated);
	}

	private static byte[] xmlKeyFile(final String version, final String dataElement) {
		return ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>" + version + "</Version>\n\t</Meta>\n\t<Key>\n\t\t" + dataElement + "\n\t</Key>\n</KeyFile>").getBytes(StandardCharsets.UTF_8);
	}

	@Test
	public void testPasswordOnly() throws Exception {
		assertArrayEquals(expectedCompositeKey(PASSWORD, null), new KdbxCredentials(PASSWORD).createCompositeKeyHash());
		// The password array is not cleared, so the credentials can be used several times
		assertArrayEquals(new KdbxCredentials(PASSWORD).createCompositeKeyHash(), new KdbxCredentials(PASSWORD).createCompositeKeyHash());
	}

	@Test
	public void testNoCredentials() throws Exception {
		assertArrayEquals(sha256(new byte[0]), new KdbxCredentials((char[]) null).createCompositeKeyHash());
	}

	@Test
	public void testRawBinaryKeyFile() throws Exception {
		// 32 bytes are used directly as key
		assertArrayEquals(expectedCompositeKey(PASSWORD, KEY), new KdbxCredentials(PASSWORD, KEY).createCompositeKeyHash());
		assertArrayEquals(expectedCompositeKey(null, KEY), new KdbxCredentials(KEY).createCompositeKeyHash());
	}

	@Test
	public void testHexKeyFile() throws Exception {
		final byte[] hexKeyFile = Utilities.toHexString(KEY, "").toLowerCase().getBytes(StandardCharsets.US_ASCII);
		assertArrayEquals(expectedCompositeKey(PASSWORD, KEY), new KdbxCredentials(PASSWORD, hexKeyFile).createCompositeKeyHash());

		// 64 characters, which are not all hexadecimal, are hashed
		final byte[] notHexKeyFile = hexKeyFile.clone();
		notHexKeyFile[10] = 'x';
		assertArrayEquals(expectedCompositeKey(PASSWORD, sha256(notHexKeyFile)), new KdbxCredentials(PASSWORD, notHexKeyFile).createCompositeKeyHash());
	}

	@Test
	public void testOtherKeyFileIsHashed() throws Exception {
		final byte[] keyFile = "Any file content can be used as key file".getBytes(StandardCharsets.UTF_8);
		assertArrayEquals(expectedCompositeKey(PASSWORD, sha256(keyFile)), new KdbxCredentials(PASSWORD, keyFile).createCompositeKeyHash());

		// XML documents, which are no KeePass key files, are hashed as well
		final byte[] otherXml = "<?xml version=\"1.0\"?><Other><Key><Data>AAAA</Data></Key></Other>".getBytes(StandardCharsets.UTF_8);
		assertArrayEquals(expectedCompositeKey(PASSWORD, sha256(otherXml)), new KdbxCredentials(PASSWORD, otherXml).createCompositeKeyHash());
	}

	@Test
	public void testXmlKeyFileVersion1() throws Exception {
		final byte[] keyFile = xmlKeyFile("1.00", "<Data>" + Base64.getEncoder().encodeToString(KEY) + "</Data>");
		assertArrayEquals(expectedCompositeKey(PASSWORD, KEY), new KdbxCredentials(PASSWORD, keyFile).createCompositeKeyHash());
	}

	@Test
	public void testXmlKeyFileVersion2() throws Exception {
		final String hexKey = Utilities.toHexString(KEY, "");
		// KeePass writes the key in groups of 8 hex digits with line breaks
		final StringBuilder formattedHexKey = new StringBuilder();
		for (int i = 0; i < hexKey.length(); i += 8) {
			formattedHexKey.append("\n\t\t\t").append(hexKey, i, i + 8);
		}
		final String hash = Utilities.toHexString(Arrays.copyOf(sha256(KEY), 4), "");

		final byte[] keyFile = xmlKeyFile("2.0", "<Data Hash=\"" + hash + "\">" + formattedHexKey + "\n\t\t</Data>");
		assertArrayEquals(expectedCompositeKey(PASSWORD, KEY), new KdbxCredentials(PASSWORD, keyFile).createCompositeKeyHash());

		// The hash is optional
		final byte[] keyFileWithoutHash = xmlKeyFile("2.0", "<Data>" + hexKey + "</Data>");
		assertArrayEquals(expectedCompositeKey(PASSWORD, KEY), new KdbxCredentials(PASSWORD, keyFileWithoutHash).createCompositeKeyHash());

		// UTF-8 byte order mark
		final byte[] keyFileWithBom = Utilities.concatArrays(new byte[] { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF }, keyFile);
		assertArrayEquals(expectedCompositeKey(PASSWORD, KEY), new KdbxCredentials(PASSWORD, keyFileWithBom).createCompositeKeyHash());
	}

	@Test
	public void testCorruptedXmlKeyFileVersion2() {
		final String hexKey = Utilities.toHexString(KEY, "");
		final byte[] wrongHash = xmlKeyFile("2.0", "<Data Hash=\"00000000\">" + hexKey + "</Data>");
		assertTrue(assertThrows(Exception.class, () -> new KdbxCredentials(PASSWORD, wrongHash).createCompositeKeyHash()).getMessage().contains("the key file is corrupted"));

		final byte[] shortHash = xmlKeyFile("2.0", "<Data Hash=\"00\">" + hexKey + "</Data>");
		assertThrows(Exception.class, () -> new KdbxCredentials(PASSWORD, shortHash).createCompositeKeyHash());
	}

	@Test
	public void testInvalidXmlKeyFiles() {
		final byte[] missingData = xmlKeyFile("2.0", "");
		assertTrue(assertThrows(Exception.class, () -> new KdbxCredentials(PASSWORD, missingData).createCompositeKeyHash()).getMessage().contains("Missing key data"));

		final byte[] blankData = xmlKeyFile("2.0", "<Data>  </Data>");
		assertTrue(assertThrows(Exception.class, () -> new KdbxCredentials(PASSWORD, blankData).createCompositeKeyHash()).getMessage().contains("Missing key data"));

		final byte[] unsupportedVersion = xmlKeyFile("3.0", "<Data>AAAA</Data>");
		assertTrue(assertThrows(Exception.class, () -> new KdbxCredentials(PASSWORD, unsupportedVersion).createCompositeKeyHash()).getMessage().contains("Unsupported XML key file version: 3.0"));

		final byte[] withoutMeta = "<?xml version=\"1.0\"?><KeyFile><Key><Data>AAAA</Data></Key></KeyFile>".getBytes(StandardCharsets.UTF_8);
		assertTrue(assertThrows(Exception.class, () -> new KdbxCredentials(PASSWORD, withoutMeta).createCompositeKeyHash()).getMessage().contains("Unsupported XML key file version: null"));

		final byte[] withoutVersion = "<?xml version=\"1.0\"?><KeyFile><Meta/><Key><Data>AAAA</Data></Key></KeyFile>".getBytes(StandardCharsets.UTF_8);
		assertThrows(Exception.class, () -> new KdbxCredentials(PASSWORD, withoutVersion).createCompositeKeyHash());
	}

	@Test
	public void testWindowsUserAccountIsNotSupported() {
		assertThrows(RuntimeException.class, () -> new KdbxCredentials("DOMAIN\\User").createCompositeKeyHash());
		assertThrows(RuntimeException.class, () -> new KdbxCredentials(PASSWORD, KEY, "DOMAIN\\User").createCompositeKeyHash());
	}
}
