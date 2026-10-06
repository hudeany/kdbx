package de.soderer.utilities.kdbx;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxEntryBinary;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat3;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat4;
import de.soderer.utilities.kdbx.data.KdbxTimes;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.data.KeyDerivationFunctionInfoArgon;
import de.soderer.utilities.kdbx.utilities.HmacInputStream;
import de.soderer.utilities.kdbx.utilities.HmacOutputStream;
import de.soderer.utilities.kdbx.utilities.IoUtilities;
import de.soderer.utilities.kdbx.utilities.Version;

/**
 * Regression tests for bugs found in the review of the KDBX library.
 * The files in "kdbx/interop" were created with pykeepass, an independent implementation of the KDBX format.
 */
@SuppressWarnings("static-method")
public class KdbxBugfixTest {
	private static final char[] TEST_PASSWORD = "test".toCharArray();

	private byte[] resource(final String path) throws Exception {
		try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path)) {
			return IoUtilities.toByteArray(inputStream);
		}
	}

	private static KdbxDatabase read(final byte[] data, final KdbxCredentials credentials) throws Exception {
		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(data))) {
			return kdbxReader.readKdbxDatabase(credentials);
		}
	}

	private static byte[] write(final KdbxDatabase database, final KdbxHeaderFormat headerFormat, final KdbxCredentials credentials) throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (KdbxWriter kdbxWriter = new KdbxWriter(outputStream)) {
			kdbxWriter.writeKdbxDatabase(database, headerFormat, credentials);
		}
		return outputStream.toByteArray();
	}

	/**
	 * Argon2 with low cost parameters to keep the tests fast
	 */
	private static KdbxHeaderFormat4 fastHeader() {
		return new KdbxHeaderFormat4().withKeyDerivationFunctionInfo(new KeyDerivationFunctionInfoArgon().withIterations(1).withMemoryInBytes(1024 * 1024).withParallelism(1));
	}

	private static KdbxDatabase createSimpleDatabase() {
		final KdbxDatabase database = new KdbxDatabase();
		final KdbxGroup group = new KdbxGroup().withName("Group");
		database.getGroups().add(group);
		group.getEntries().add(new KdbxEntry().withTitle("Title").withUsername("User").withPassword("Secret"));
		return database;
	}

	@Test
	public void testV3PayloadWithSeveralHashedBlocks() throws Exception {
		final KdbxDatabase database = read(resource("kdbx/interop/v3_multiblock.kdbx"), new KdbxCredentials("Äbc123@".toCharArray()));
		int largestAttachment = 0;
		for (final KdbxEntry entry : database.getAllEntries()) {
			for (final KdbxEntryBinary binary : entry.getBinaries()) {
				largestAttachment = Math.max(largestAttachment, binary.getData().length);
			}
		}
		assertEquals(1200 * 1024, largestAttachment);
	}

	@Test
	public void testV3WriteAndReadSeveralHashedBlocks() throws Exception {
		final KdbxDatabase database = createSimpleDatabase();
		final byte[] attachmentData = new byte[3 * 1024 * 1024];
		new java.util.Random(42).nextBytes(attachmentData);
		database.getAllEntries().get(0).getBinaries().add(new KdbxEntryBinary().withKey("big.bin").withData(attachmentData));
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);
		final KdbxDatabase database2 = read(write(database, new KdbxHeaderFormat3().withTransformRounds(1000), credentials), credentials);
		assertArrayEquals(attachmentData, database2.getAllEntries().get(0).getBinaries().get(0).getData());
	}

	@Test
	public void testV4ProtectedAttachmentsAndCustomFields() throws Exception {
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);
		final KdbxDatabase database = read(resource("kdbx/interop/v4_protected_attachments.kdbx"), credentials);
		final KdbxEntry entry = database.getAllEntries().get(0);
		assertEquals(3, entry.getBinaries().size());
		assertEquals("second attachment", new String(entry.getBinaries().get(1).getData(), StandardCharsets.UTF_8));
		assertEquals("1234", entry.getItem("PIN"));
		assertTrue(entry.isItemProtected("PIN"));
		assertFalse(entry.isItemProtected("Plain"));

		// Protected custom fields stay protected after writing
		final KdbxEntry entry2 = read(write(database, fastHeader(), credentials), credentials).getAllEntries().get(0);
		assertEquals("1234", entry2.getItem("PIN"));
		assertTrue(entry2.isItemProtected("PIN"));
		assertFalse(entry2.isItemProtected("Plain"));
		assertEquals("visible", entry2.getItem("Plain"));
	}

	@Test
	public void testHexKeyFileWithLineBreakIsHashed() throws Exception {
		read(resource("kdbx/interop/keyfile_hex_newline.kdbx"), new KdbxCredentials(TEST_PASSWORD, resource("kdbx/interop/keyfile_hex_newline.key")));
	}

	@Test
	public void testInvalidXmlKeyFileIsHashed() throws Exception {
		read(resource("kdbx/interop/keyfile_invalid_xml.kdbx"), new KdbxCredentials(TEST_PASSWORD, resource("kdbx/interop/keyfile_invalid_xml.key")));
	}

	@Test
	public void testAutoTypeAssociation() throws Exception {
		final KdbxDatabase database = createSimpleDatabase();
		database.getAllEntries().get(0).setAutoType(true, "0", "{USERNAME}", "Login - Browser", "{PASSWORD}{ENTER}");
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);
		final KdbxEntry entry = read(write(database, fastHeader(), credentials), credentials).getAllEntries().get(0);
		assertEquals("Login - Browser", entry.getAutoTypeAssociationWindow());
		assertEquals("{PASSWORD}{ENTER}", entry.getAutoTypeAssociationKeystrokeSequence());
	}

	@Test
	public void testFreshCryptoValuesForEachWrite() throws Exception {
		final KdbxDatabase database = createSimpleDatabase();
		final KdbxHeaderFormat4 headerFormat = fastHeader().withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.CHACHA20);
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);
		final KdbxHeaderFormat4 header1 = KdbxHeaderFormat4.read(new ByteArrayInputStream(write(database, headerFormat, credentials)));
		final KdbxHeaderFormat4 header2 = KdbxHeaderFormat4.read(new ByteArrayInputStream(write(database, headerFormat, credentials)));
		assertFalse(Arrays.equals(header1.getEncryptionIV(), header2.getEncryptionIV()));
		assertFalse(Arrays.equals(header1.getMasterSeed(), header2.getMasterSeed()));
	}

	@Test
	public void testAttachmentsSurviveSecondWrite() throws Exception {
		final KdbxDatabase database = createSimpleDatabase();
		database.getAllEntries().get(0).getBinaries().add(new KdbxEntryBinary().withKey("a.txt").withData("hello".getBytes(StandardCharsets.UTF_8)));
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);
		write(database, fastHeader(), credentials);
		final KdbxDatabase database2 = read(write(database, fastHeader(), credentials), credentials);
		assertEquals("hello", new String(database2.getAllEntries().get(0).getBinaries().get(0).getData(), StandardCharsets.UTF_8));
	}

	@Test
	public void testAttachmentsOfHistoryEntries() throws Exception {
		final KdbxDatabase database = createSimpleDatabase();
		final KdbxEntry entry = database.getAllEntries().get(0);
		entry.getBinaries().add(new KdbxEntryBinary().withKey("current.txt").withData("current".getBytes(StandardCharsets.UTF_8)));
		final KdbxEntry historyEntry = new KdbxEntry().withUuid(entry.getUuid()).withTitle("Old");
		historyEntry.getBinaries().add(new KdbxEntryBinary().withKey("old.txt").withData("old version".getBytes(StandardCharsets.UTF_8)));
		entry.getHistory().add(historyEntry);
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);

		for (final KdbxHeaderFormat headerFormat : new KdbxHeaderFormat[] { fastHeader(), new KdbxHeaderFormat3().withTransformRounds(1000) }) {
			final KdbxEntry entry2 = read(write(database, headerFormat, credentials), credentials).getAllEntries().get(0);
			assertEquals("current", new String(entry2.getBinaries().get(0).getData(), StandardCharsets.UTF_8));
			assertEquals("old version", new String(entry2.getHistory().get(0).getBinaries().get(0).getData(), StandardCharsets.UTF_8));
		}
	}

	@Test
	public void testNewGroupWithoutOptionalValues() throws Exception {
		final KdbxDatabase database = new KdbxDatabase();
		final KdbxGroup group = new KdbxGroup().withName("Group");
		database.getGroups().add(group);
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);
		final KdbxGroup group2 = read(write(database, fastHeader(), credentials), credentials).getGroups().get(0);
		assertEquals("Group", group2.getName());
		assertNull(group2.getIconID());
		// "null" means inherit from the parent group and must not become "False"
		assertNull(group2.getEnableAutoTypeSetting());
		assertNull(group2.getEnableSearchingSetting());
		assertTrue(group2.isEnableAutoType());
	}

	@Test
	public void testMasterKeyChangedOnlyOnChangedCredentials() throws Exception {
		final KdbxDatabase database = createSimpleDatabase();
		final ZonedDateTime oldTime = ZonedDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);

		// First write of a new database: the key is new
		write(database, fastHeader(), credentials);
		assertTrue(database.getMeta().getMasterKeyChanged().isAfter(oldTime));

		// Read and write with the same credentials keeps the value
		database.getMeta().setMasterKeyChanged(oldTime);
		final KdbxDatabase database2 = read(write(database, fastHeader(), credentials), credentials);
		assertTrue(oldTime.isEqual(database2.getMeta().getMasterKeyChanged()));
		write(database2, fastHeader(), credentials);
		assertTrue(oldTime.isEqual(database2.getMeta().getMasterKeyChanged()));

		// Writing with other credentials updates the value
		write(database2, fastHeader(), new KdbxCredentials("other".toCharArray()));
		assertTrue(database2.getMeta().getMasterKeyChanged().isAfter(oldTime));
	}

	@Test
	public void testV3DateFormat() throws Exception {
		final Method formatMethod = KdbxWriter.class.getDeclaredMethod("formatDateTimeValue", Version.class, ZonedDateTime.class);
		formatMethod.setAccessible(true);
		final ZonedDateTime dateTime = ZonedDateTime.of(2024, 7, 1, 14, 30, 15, 123_000_000, ZoneId.of("Europe/Berlin"));
		assertEquals("2024-07-01T12:30:15Z", formatMethod.invoke(null, new Version(3, 1, 0), dateTime));
	}

	@Test
	public void testUuidPathAndGroupLookup() {
		final KdbxDatabase database = new KdbxDatabase();
		final KdbxGroup group1 = new KdbxGroup().withName("G1");
		final KdbxGroup group2 = new KdbxGroup().withName("G2");
		final KdbxEntry entry = new KdbxEntry().withTitle("E");
		database.getGroups().add(group1);
		group1.getGroups().add(group2);
		group2.getEntries().add(entry);

		final List<KdbxUUID> expectedPath = Arrays.asList(group1.getUuid(), group2.getUuid(), entry.getUuid());
		assertEquals(expectedPath, database.getUuidPath(entry.getUuid()));
		assertEquals(Arrays.asList(group1.getUuid(), group2.getUuid()), database.getUuidPath(group2.getUuid()));
		assertTrue(database.getGroupByUUID(group2.getUuid()) == group2);
	}

	@Test
	public void testHmacInputStreamReadWithOffset() throws Exception {
		final byte[] key = new byte[64];
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (HmacOutputStream hmacOutputStream = new HmacOutputStream(outputStream, key)) {
			hmacOutputStream.write(new byte[10]);
		}
		try (HmacInputStream hmacInputStream = new HmacInputStream(new ByteArrayInputStream(outputStream.toByteArray()), key)) {
			assertEquals(10, hmacInputStream.read(new byte[100], 50, 20));
			assertEquals(-1, hmacInputStream.read(new byte[100], 50, 20));
		}
	}

	@Test
	public void testTruncatedV4IsRejected() throws Exception {
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);
		final byte[] data = write(createSimpleDatabase(), fastHeader().withCompressData(false).withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.CHACHA20), credentials);
		// Remove the terminating empty HMAC block (32 bytes HMAC + 4 bytes length)
		final byte[] truncatedData = Arrays.copyOf(data, data.length - 36);
		assertThrows(Exception.class, () -> read(truncatedData, credentials));
	}

	@Test
	public void testStreamWithSingleByteReads() throws Exception {
		final byte[] data = resource("kdbx/interop/v4_protected_attachments.kdbx");
		final InputStream trickleInputStream = new FilterInputStream(new ByteArrayInputStream(data)) {
			@Override
			public int read(final byte[] buffer, final int offset, final int length) throws IOException {
				return super.read(buffer, offset, Math.min(length, 1));
			}

			@Override
			public int available() {
				return 0;
			}
		};
		try (KdbxReader kdbxReader = new KdbxReader(trickleInputStream)) {
			assertEquals(3, kdbxReader.readKdbxDatabase(TEST_PASSWORD).getAllEntries().get(0).getBinaries().size());
		}
	}

	@Test
	public void testExcessiveV3TransformRounds() {
		assertThrows(IllegalArgumentException.class, () -> new KdbxHeaderFormat3().setTransformRounds(Long.MAX_VALUE));
		assertThrows(IllegalArgumentException.class, () -> new KdbxHeaderFormat3().setTransformRounds(-1));
	}

	@Test
	public void testNonStringItemValueAndMasterKeyChangeForceOnce() throws Exception {
		final KdbxDatabase database = createSimpleDatabase();
		database.getAllEntries().get(0).setItem("Number", 42);
		database.getMeta().setMasterKeyChangeForceOnce(true);
		final KdbxCredentials credentials = new KdbxCredentials(TEST_PASSWORD);
		final KdbxDatabase database2 = read(write(database, fastHeader(), credentials), credentials);
		assertEquals("42", database2.getAllEntries().get(0).getItem("Number"));
		assertTrue(database2.getMeta().isMasterKeyChangeForceOnce());
	}

	@Test
	public void testKdbxTimesHashCodeMatchesEquals() {
		final ZonedDateTime utcTime = ZonedDateTime.of(2024, 1, 1, 12, 0, 0, 0, ZoneId.of("UTC"));
		final KdbxTimes times1 = new KdbxTimes().withCreationTime(utcTime).withLastModificationTime(utcTime);
		final KdbxTimes times2 = new KdbxTimes().withCreationTime(utcTime.withZoneSameInstant(ZoneId.of("Europe/Berlin"))).withLastModificationTime(utcTime);
		assertEquals(times1, times2);
		assertEquals(times1.hashCode(), times2.hashCode());
	}
}
