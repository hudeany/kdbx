package de.soderer.utilities.kdbx;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

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
import de.soderer.utilities.kdbx.data.KeyDerivationFunctionInfoAes;
import de.soderer.utilities.kdbx.data.KeyDerivationFunctionInfoArgon;
import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * Tests of {@link KdbxWriter} and {@link KdbxDatabase}: complete round trips in KDBX 3 and KDBX 4, all supported algorithms,
 * protected values, attachments, the validation before writing and the errors for unsupported settings.
 */
@SuppressWarnings("static-method")
public class KdbxWriterTest {
	private static final KdbxCredentials CREDENTIALS = new KdbxCredentials("writer-test".toCharArray());
	private static final ZonedDateTime TIME = ZonedDateTime.of(2022, 2, 3, 4, 5, 6, 0, ZoneId.of("UTC"));

	private static KdbxHeaderFormat4 fastHeader4() {
		return new KdbxHeaderFormat4().withKeyDerivationFunctionInfo(new KeyDerivationFunctionInfoAes().withAesTransformRounds(10));
	}

	private static KdbxHeaderFormat3 fastHeader3() {
		return new KdbxHeaderFormat3().withTransformRounds(10);
	}

	private static byte[] write(final KdbxDatabase database, final KdbxHeaderFormat headerFormat) throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (KdbxWriter kdbxWriter = new KdbxWriter(outputStream)) {
			kdbxWriter.writeKdbxDatabase(database, headerFormat, CREDENTIALS);
		}
		return outputStream.toByteArray();
	}

	private static KdbxDatabase read(final byte[] data) throws Exception {
		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(data))) {
			kdbxReader.withStrictMode(true);
			return kdbxReader.readKdbxDatabase(CREDENTIALS);
		}
	}

	private static KdbxDatabase roundTrip(final KdbxDatabase database, final KdbxHeaderFormat headerFormat) throws Exception {
		return read(write(database, headerFormat));
	}

	private static KdbxTimes fullTimes() {
		return new KdbxTimes().withCreationTime(TIME).withLastModificationTime(TIME.plusHours(1)).withLastAccessTime(TIME.plusHours(2)).withExpiryTime(TIME.plusDays(30))
				.withExpires(true).withUsageCount(9).withLocationChanged(TIME.plusHours(3));
	}

	private static void assertTime(final ZonedDateTime expected, final ZonedDateTime actual) {
		assertTrue(expected.isEqual(actual), "Expected " + expected + " but was " + actual);
	}

	private static void assertTimes(final KdbxTimes expected, final KdbxTimes actual) {
		// Equality of KdbxTimes compares the instants independent of the time zone
		assertEquals(expected, actual);
	}

	/**
	 * Creates a database, which uses every value supported by the writer
	 */
	private static KdbxDatabase createFullDatabase() throws Exception {
		final KdbxDatabase database = new KdbxDatabase();
		final KdbxUUID iconUuid = KdbxUUID.fromHex("0123456789ABCDEF0123456789ABCDEF");
		final Map<KdbxUUID, byte[]> customIcons = new LinkedHashMap<>();
		customIcons.put(iconUuid, new byte[] { (byte) 0x89, 'P', 'N', 'G' });

		final KdbxGroup group = new KdbxGroup().withName("Group").withNotes("Group notes").withIconID(48).withExpanded(true).withDefaultAutoTypeSequence("{TAB}")
				.withEnableAutoTypeSetting(Boolean.FALSE).withEnableSearchingSetting(Boolean.TRUE).withTimes(fullTimes()).withCustomIconUuid(iconUuid)
				.withCustomData(new ArrayList<>(Arrays.asList(new KdbxCustomDataItem().withKey("GroupKey").withValue("GroupValue").withLastModificationTime(TIME))));
		final KdbxGroup subGroup = new KdbxGroup().withName("Sub group");
		group.getGroups().add(subGroup);
		database.getGroups().add(group);

		final KdbxEntry entry = new KdbxEntry().withTitle("Title").withUsername("User").withPassword("P\u00e4ssw\u00f6rd").withUrl("https://example.com").withNotes("Line 1\nLine 2")
				.withIconID(1).withCustomIconUuid(iconUuid).withForegroundColor("#112233").withBackgroundColor("#445566").withOverrideURL("cmd://browser %1").withTags("tag")
				.withTimes(fullTimes()).withItem("Custom", "Custom value").withItem("Secret custom", "hidden").withItemProtected("Secret custom", true).withItem("Null value", null)
				.withAutoType(true, "1", "{USERNAME}{TAB}{PASSWORD}", "Login*", "{PASSWORD}{ENTER}")
				.withCustomData(new ArrayList<>(Arrays.asList(new KdbxCustomDataItem().withKey("EntryKey").withValue("EntryValue"))));
		entry.getBinaries().add(new KdbxEntryBinary().withKey("a.txt").withData("attachment".getBytes(StandardCharsets.UTF_8)));
		final KdbxEntry historyEntry = new KdbxEntry().withUuid(entry.getUuid()).withTitle("Title").withPassword("Old password");
		entry.getHistory().add(historyEntry);
		group.getEntries().add(entry);
		group.setLastTopVisibleEntry(entry.getUuid());

		database.getEntries().add(new KdbxEntry().withTitle("Root entry"));
		database.getDeletedObjects().put(new KdbxUUID(), TIME);

		final KdbxMeta meta = database.getMeta();
		meta.setGenerator("KdbxWriterTest");
		meta.setSettingsChanged(TIME);
		meta.setDatabaseName("Database");
		meta.setDatabaseNameChanged(TIME);
		meta.setDatabaseDescription("Description");
		meta.setDatabaseDescriptionChanged(TIME);
		meta.setDefaultUserName("Default user");
		meta.setDefaultUserNameChanged(TIME);
		meta.setMaintenanceHistoryDays(365);
		meta.setColor("#FF0000");
		meta.setMasterKeyChangeRec(10);
		meta.setMasterKeyChangeForce(20);
		meta.setMasterKeyChangeForceOnce(true);
		meta.setRecycleBinEnabled(true);
		meta.setRecycleBinUUID(subGroup.getUuid());
		meta.setRecycleBinChanged(TIME);
		meta.setEntryTemplatesGroup(group.getUuid());
		meta.setEntryTemplatesGroupChanged(TIME);
		meta.setHistoryMaxItems(10);
		meta.setHistoryMaxSize(6 * 1024 * 1024);
		meta.setLastSelectedGroup(group.getUuid());
		meta.setLastTopVisibleGroup(subGroup.getUuid());
		meta.setMemoryProtection(new KdbxMemoryProtection().withProtectTitle(true).withProtectUserName(true).withProtectPassword(true).withProtectURL(true).withProtectNotes(true));
		meta.setCustomIcons(customIcons);
		meta.setCustomData(new ArrayList<>(Arrays.asList(new KdbxCustomDataItem().withKey("MetaKey").withValue("MetaValue").withLastModificationTime(TIME))));
		return database;
	}

	private static void assertFullDatabase(final KdbxDatabase original, final KdbxDatabase database) throws Exception {
		final KdbxMeta originalMeta = original.getMeta();
		final KdbxMeta meta = database.getMeta();
		assertEquals("KdbxWriterTest", meta.getGenerator());
		assertTime(TIME, meta.getSettingsChanged());
		assertEquals("Database", meta.getDatabaseName());
		assertTime(TIME, meta.getDatabaseNameChanged());
		assertEquals("Description", meta.getDatabaseDescription());
		assertTime(TIME, meta.getDatabaseDescriptionChanged());
		assertEquals("Default user", meta.getDefaultUserName());
		assertTime(TIME, meta.getDefaultUserNameChanged());
		assertEquals(365, meta.getMaintenanceHistoryDays());
		assertEquals("#FF0000", meta.getColor());
		assertTrue(meta.getMasterKeyChanged() != null);
		assertEquals(10, meta.getMasterKeyChangeRec());
		assertEquals(20, meta.getMasterKeyChangeForce());
		assertTrue(meta.isMasterKeyChangeForceOnce());
		assertTrue(meta.isRecycleBinEnabled());
		assertEquals(originalMeta.getRecycleBinUUID(), meta.getRecycleBinUUID());
		assertTime(TIME, meta.getRecycleBinChanged());
		assertEquals(originalMeta.getEntryTemplatesGroup(), meta.getEntryTemplatesGroup());
		assertTime(TIME, meta.getEntryTemplatesGroupChanged());
		assertEquals(10, meta.getHistoryMaxItems());
		assertEquals(6 * 1024 * 1024, meta.getHistoryMaxSize());
		assertEquals(originalMeta.getLastSelectedGroup(), meta.getLastSelectedGroup());
		assertEquals(originalMeta.getLastTopVisibleGroup(), meta.getLastTopVisibleGroup());
		assertTrue(meta.getMemoryProtection().isProtectTitle());
		assertTrue(meta.getMemoryProtection().isProtectUserName());
		assertTrue(meta.getMemoryProtection().isProtectURL());
		assertTrue(meta.getMemoryProtection().isProtectNotes());
		assertEquals(1, meta.getCustomIcons().size());
		assertArrayEquals(originalMeta.getCustomIcons().values().iterator().next(), meta.getCustomIcons().values().iterator().next());
		assertEquals("MetaValue", meta.getCustomData().get(0).getValue());
		assertTime(TIME, meta.getCustomData().get(0).getLastModificationTime());

		final KdbxGroup originalGroup = original.getGroups().get(0);
		final KdbxGroup group = database.getGroups().get(0);
		assertEquals(originalGroup.getUuid(), group.getUuid());
		assertEquals("Group", group.getName());
		assertEquals("Group notes", group.getNotes());
		assertEquals(48, group.getIconID());
		assertTrue(group.isExpanded());
		assertEquals("{TAB}", group.getDefaultAutoTypeSequence());
		assertEquals(Boolean.FALSE, group.getEnableAutoTypeSetting());
		assertEquals(Boolean.TRUE, group.getEnableSearchingSetting());
		assertEquals(originalGroup.getLastTopVisibleEntry(), group.getLastTopVisibleEntry());
		assertEquals(originalGroup.getCustomIconUuid(), group.getCustomIconUuid());
		assertEquals("GroupValue", group.getCustomData().get(0).getValue());
		assertTimes(originalGroup.getTimes(), group.getTimes());
		assertEquals("Sub group", group.getGroups().get(0).getName());
		assertNull(group.getGroups().get(0).getIconID());

		final KdbxEntry originalEntry = originalGroup.getEntries().get(0);
		final KdbxEntry entry = group.getEntries().get(0);
		assertEquals(originalEntry.getUuid(), entry.getUuid());
		assertEquals("Title", entry.getTitle());
		assertEquals("User", entry.getUsername());
		assertEquals("P\u00e4ssw\u00f6rd", entry.getPassword());
		assertEquals("https://example.com", entry.getUrl());
		assertEquals("Line 1\nLine 2", entry.getNotes());
		assertEquals(1, entry.getIconID());
		assertEquals(originalEntry.getCustomIconUuid(), entry.getCustomIconUuid());
		assertEquals("#112233", entry.getForegroundColor());
		assertEquals("#445566", entry.getBackgroundColor());
		assertEquals("cmd://browser %1", entry.getOverrideURL());
		assertEquals("tag", entry.getTags());
		assertTimes(originalEntry.getTimes(), entry.getTimes());
		assertEquals("Custom value", entry.getItem("Custom"));
		assertEquals("hidden", entry.getItem("Secret custom"));
		assertTrue(entry.isItemProtected("Secret custom"));
		assertFalse(entry.isItemProtected("Custom"));
		// Standard items are protected by the memory protection settings
		assertTrue(entry.isItemProtected("Title"));
		assertTrue(entry.getItems().containsKey("Null value"));
		assertNull(entry.getItem("Null value"));
		assertTrue(entry.isAutoTypeEnabled());
		assertEquals("1", entry.getAutoTypeDataTransferObfuscation());
		assertEquals("{USERNAME}{TAB}{PASSWORD}", entry.getAutoTypeDefaultSequence());
		assertEquals("Login*", entry.getAutoTypeAssociationWindow());
		assertEquals("{PASSWORD}{ENTER}", entry.getAutoTypeAssociationKeystrokeSequence());
		assertEquals("EntryValue", entry.getCustomData().get(0).getValue());
		assertEquals("attachment", new String(entry.getBinaries().get(0).getData(), StandardCharsets.UTF_8));
		assertEquals("Old password", entry.getHistory().get(0).getPassword());

		assertEquals("Root entry", database.getEntries().get(0).getTitle());
		assertEquals(original.getDeletedObjects().keySet(), database.getDeletedObjects().keySet());
		assertTime(TIME, database.getDeletedObjects().values().iterator().next());
	}

	// ---- Round trips ----

	@Test
	public void testFullRoundTripKdbx4() throws Exception {
		final KdbxDatabase database = createFullDatabase();
		final KdbxDatabase readDatabase = roundTrip(database, fastHeader4());
		assertFullDatabase(database, readDatabase);
		assertEquals("4.1.0", readDatabase.getHeaderFormat().getDataFormatVersion().toString());
	}

	@Test
	public void testFullRoundTripKdbx3() throws Exception {
		final KdbxDatabase database = createFullDatabase();
		final KdbxDatabase readDatabase = roundTrip(database, fastHeader3().withInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.SALSA20));
		assertFullDatabase(database, readDatabase);
		assertEquals("3.1.0", readDatabase.getHeaderFormat().getDataFormatVersion().toString());
		assertTrue(Utilities.isNotBlank(readDatabase.getMeta().getHeaderHash()));
	}

	@Test
	public void testKdbx4AlgorithmCombinations() throws Exception {
		final KdbxDatabase database = createFullDatabase();
		for (final OuterEncryptionAlgorithm outerEncryptionAlgorithm : new OuterEncryptionAlgorithm[] { OuterEncryptionAlgorithm.AES_128, OuterEncryptionAlgorithm.AES_256, OuterEncryptionAlgorithm.CHACHA20 }) {
			for (final InnerEncryptionAlgorithm innerEncryptionAlgorithm : new InnerEncryptionAlgorithm[] { InnerEncryptionAlgorithm.SALSA20, InnerEncryptionAlgorithm.CHACHA20 }) {
				for (final boolean compressData : new boolean[] { true, false }) {
					final KdbxHeaderFormat4 header = fastHeader4().withOuterEncryptionAlgorithm(outerEncryptionAlgorithm).withInnerEncryptionAlgorithm(innerEncryptionAlgorithm).withCompressData(compressData);
					final KdbxDatabase readDatabase = roundTrip(database, header);
					final String combination = outerEncryptionAlgorithm + "/" + innerEncryptionAlgorithm + "/" + compressData;
					assertEquals("P\u00e4ssw\u00f6rd", readDatabase.getGroups().get(0).getEntries().get(0).getPassword(), combination);
					final KdbxHeaderFormat4 readHeader = (KdbxHeaderFormat4) readDatabase.getHeaderFormat();
					assertSame(outerEncryptionAlgorithm, readHeader.getOuterEncryptionAlgorithm(), combination);
					assertSame(innerEncryptionAlgorithm, readHeader.getInnerEncryptionAlgorithm(), combination);
					assertEquals(compressData, readHeader.isCompressData(), combination);
				}
			}
		}
	}

	@Test
	public void testKdbx4KeyDerivationFunctions() throws Exception {
		final KdbxDatabase database = createFullDatabase();
		final KeyDerivationFunctionInfoAes aesKdbx4 = new KeyDerivationFunctionInfoAes().withAesTransformRounds(10);
		aesKdbx4.setAesKdbxType(KeyDerivationFunctionInfoAes.KdbxType.AES_KDBX4);
		final KeyDerivationFunctionInfoArgon argon2id = new KeyDerivationFunctionInfoArgon().withType(KeyDerivationFunctionInfoArgon.Argon2Type.Argon2_ID).withIterations(1).withMemoryInBytes(1024 * 1024).withParallelism(1);
		for (final KdbxHeaderFormat4 header : new KdbxHeaderFormat4[] { new KdbxHeaderFormat4().withKeyDerivationFunctionInfo(aesKdbx4), new KdbxHeaderFormat4().withKeyDerivationFunctionInfo(argon2id) }) {
			assertEquals("Title", roundTrip(database, header).getGroups().get(0).getEntries().get(0).getTitle());
		}
	}

	@Test
	public void testKdbx3Variants() throws Exception {
		final KdbxDatabase database = createFullDatabase();
		for (final boolean compressData : new boolean[] { true, false }) {
			for (final InnerEncryptionAlgorithm innerEncryptionAlgorithm : new InnerEncryptionAlgorithm[] { InnerEncryptionAlgorithm.SALSA20, InnerEncryptionAlgorithm.CHACHA20 }) {
				final KdbxHeaderFormat3 header = fastHeader3().withCompressData(compressData).withInnerEncryptionAlgorithm(innerEncryptionAlgorithm).withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.AES_128);
				final KdbxDatabase readDatabase = roundTrip(database, header);
				assertEquals("P\u00e4ssw\u00f6rd", readDatabase.getGroups().get(0).getEntries().get(0).getPassword());
				assertEquals(compressData, readDatabase.getHeaderFormat().isCompressData());
			}
		}
	}

	@Test
	public void testRewriteReadDatabaseInOtherFormat() throws Exception {
		// A database read from KDBX 4 is written as KDBX 3 and back, the attachments are converted between inner header and meta data
		final KdbxDatabase database4 = roundTrip(createFullDatabase(), fastHeader4());
		final KdbxDatabase database3 = roundTrip(database4, fastHeader3());
		assertEquals("attachment", new String(database3.getGroups().get(0).getEntries().get(0).getBinaries().get(0).getData(), StandardCharsets.UTF_8));
		final KdbxDatabase database4Again = roundTrip(database3, fastHeader4());
		assertEquals("attachment", new String(database4Again.getGroups().get(0).getEntries().get(0).getBinaries().get(0).getData(), StandardCharsets.UTF_8));
	}

	@Test
	public void testAdditionalKeyNamesToEncrypt() throws Exception {
		final KdbxDatabase database = new KdbxDatabase();
		database.getMeta().setMemoryProtection(new KdbxMemoryProtection().withProtectPassword(false));
		database.getEntries().add(new KdbxEntry().withTitle("T").withPassword("P").withItem("Token", "abc").withItem("KPRPC JSON", "{}"));

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (KdbxWriter kdbxWriter = new KdbxWriter(outputStream)) {
			kdbxWriter.withAdditionalKeyNamesToEncrypt(Collections.singleton("Token"));
			kdbxWriter.writeKdbxDatabase(database, fastHeader4(), CREDENTIALS);
		}
		final KdbxEntry entry = read(outputStream.toByteArray()).getEntries().get(0);
		assertTrue(entry.isItemProtected("Token"));
		// The KeePassRPC data is always protected
		assertTrue(entry.isItemProtected("KPRPC JSON"));
		assertFalse(entry.isItemProtected("Password"));
		assertEquals("abc", entry.getItem("Token"));
	}

	@Test
	public void testWriterConvenienceMethods() throws Exception {
		final KdbxDatabase database = new KdbxDatabase();
		database.getEntries().add(new KdbxEntry().withTitle("Convenience"));

		final ByteArrayOutputStream defaultFormatStream = new ByteArrayOutputStream();
		try (KdbxWriter kdbxWriter = new KdbxWriter(defaultFormatStream)) {
			kdbxWriter.writeKdbxDatabase(database, new KdbxCredentials("pw".toCharArray()));
		}
		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(defaultFormatStream.toByteArray()))) {
			final KdbxDatabase readDatabase = kdbxReader.readKdbxDatabase("pw".toCharArray());
			assertEquals("Convenience", readDatabase.getEntries().get(0).getTitle());
			// The default format is KDBX 4 with Argon2d
			assertTrue(((KdbxHeaderFormat4) readDatabase.getHeaderFormat()).getKeyDerivationFunctionInfo() instanceof KeyDerivationFunctionInfoArgon);
		}

		final ByteArrayOutputStream givenFormatStream = new ByteArrayOutputStream();
		try (KdbxWriter kdbxWriter = new KdbxWriter(givenFormatStream)) {
			kdbxWriter.writeKdbxDatabase(database, fastHeader3(), "pw".toCharArray());
		}
		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(givenFormatStream.toByteArray()))) {
			assertEquals("3.1.0", kdbxReader.readKdbxDatabase("pw".toCharArray()).getHeaderFormat().getDataFormatVersion().toString());
		}
	}

	@Test
	public void testWriterCloseWithoutOutputStream() throws Exception {
		new KdbxWriter(null).close();
	}

	@Test
	public void testConvertXmlWithDefaultEncoding() throws Exception {
		final org.w3c.dom.Document document = Utilities.createNewDocument();
		Utilities.appendTextValueNode(Utilities.appendNode(document, "Root"), "Text", "\u00e4");
		final String xml = new String(KdbxWriter.convertXML2ByteArray(document, null), StandardCharsets.UTF_8);
		assertTrue(xml.contains("UTF-8"));
		assertTrue(xml.contains("<Text>\u00e4</Text>"));
	}

	// ---- Unsupported settings ----

	@Test
	public void testUnsupportedAlgorithms() {
		final KdbxDatabase database = createSimpleDatabase();
		final Exception twofish4 = assertThrows(Exception.class, () -> write(database, fastHeader4().withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.TWOFISH)));
		assertTrue(twofish4.getMessage().contains("TWOFISH is not implemented yet"));
		final Exception chaCha3 = assertThrows(Exception.class, () -> write(database, fastHeader3().withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.CHACHA20)));
		assertTrue(chaCha3.getMessage().contains("Encryption failed"));
		assertThrows(Exception.class, () -> write(database, fastHeader4().withInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.NONE)));
		assertThrows(Exception.class, () -> write(database, fastHeader4().withInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.ARC4_VARIANT)));
	}

	// ---- Validation ----

	private static KdbxDatabase createSimpleDatabase() {
		final KdbxDatabase database = new KdbxDatabase();
		final KdbxGroup group = new KdbxGroup().withName("Group");
		group.getEntries().add(new KdbxEntry().withTitle("Entry"));
		database.getGroups().add(group);
		return database;
	}

	@Test
	public void testValidateDuplicateUuids() {
		final KdbxDatabase duplicateGroups = createSimpleDatabase();
		duplicateGroups.getGroups().add(new KdbxGroup().withUuid(duplicateGroups.getGroups().get(0).getUuid()));
		assertTrue(assertThrows(Exception.class, duplicateGroups::validate).getMessage().contains("Group with duplicate UUID found"));

		final KdbxDatabase duplicateEntries = createSimpleDatabase();
		duplicateEntries.getEntries().add(new KdbxEntry().withUuid(duplicateEntries.getAllEntries().get(0).getUuid()));
		assertTrue(assertThrows(Exception.class, duplicateEntries::validate).getMessage().contains("Entry with duplicate UUID found"));

		// Groups and entries share the UUID space
		final KdbxDatabase entryWithGroupUuid = createSimpleDatabase();
		entryWithGroupUuid.getEntries().add(new KdbxEntry().withUuid(entryWithGroupUuid.getGroups().get(0).getUuid()));
		assertThrows(Exception.class, entryWithGroupUuid::validate);
	}

	@Test
	public void testValidateIconIds() {
		final KdbxDatabase invalidGroupIcon = createSimpleDatabase();
		invalidGroupIcon.getGroups().get(0).setIconID(1000);
		assertTrue(assertThrows(Exception.class, invalidGroupIcon::validate).getMessage().contains("Invalid standard icon id found in group 'Group': 1000"));

		final KdbxDatabase invalidEntryIcon = createSimpleDatabase();
		invalidEntryIcon.getAllEntries().get(0).setIconID(-1);
		assertTrue(assertThrows(Exception.class, invalidEntryIcon::validate).getMessage().contains("Invalid standard icon id found in entry 'Entry': -1"));
	}

	@Test
	public void testValidateAttachments() throws Exception {
		final KdbxDatabase withoutData = createSimpleDatabase();
		withoutData.getAllEntries().get(0).getBinaries().add(new KdbxEntryBinary().withKey("empty.bin"));
		assertTrue(assertThrows(Exception.class, withoutData::validate).getMessage().contains("Attachment 'empty.bin' of entry 'Entry'"));

		// The same attachment data is stored only once
		final KdbxDatabase sameData = createSimpleDatabase();
		final KdbxEntry entry1 = sameData.getAllEntries().get(0);
		final KdbxEntry entry2 = new KdbxEntry().withTitle("Entry 2");
		sameData.getEntries().add(entry2);
		entry1.getBinaries().add(new KdbxEntryBinary().withKey("a").withData(new byte[] { 1, 2, 3 }));
		entry2.getBinaries().add(new KdbxEntryBinary().withKey("b").withData(new byte[] { 1, 2, 3 }));
		entry2.getBinaries().add(new KdbxEntryBinary().withKey("c").withData(new byte[] { 4 }));
		sameData.validate();
		assertEquals(2, sameData.getBinaryAttachments().size());
		assertEquals(Integer.valueOf(0), entry1.getBinaries().get(0).getRefId());
		assertEquals(Integer.valueOf(0), entry2.getBinaries().get(0).getRefId());
		assertEquals(Integer.valueOf(1), entry2.getBinaries().get(1).getRefId());

		// Attachments without data, but with a reference to a known binary, keep their data
		final KdbxEntry entry3 = new KdbxEntry().withTitle("Entry 3");
		entry3.getBinaries().add(new KdbxEntryBinary().withKey("ref").withRefId(1));
		sameData.getEntries().add(entry3);
		sameData.validate();
		assertEquals(2, sameData.getBinaryAttachments().size());
		assertArrayEquals(new byte[] { 4 }, Utilities.gunzip(sameData.getBinaryAttachments().get(entry3.getBinaries().get(0).getRefId()).getData()));

		// A reference to an unknown binary is an error
		entry3.getBinaries().add(new KdbxEntryBinary().withKey("unknown").withRefId(99));
		assertThrows(Exception.class, sameData::validate);
	}

	// ---- Database ----

	@Test
	public void testDatabaseLookups() {
		final KdbxDatabase database = createSimpleDatabase();
		final KdbxGroup group = database.getGroups().get(0);
		final KdbxGroup subGroup = new KdbxGroup().withName("Sub");
		group.getGroups().add(subGroup);
		final KdbxEntry rootEntry = new KdbxEntry().withTitle("Root entry");
		database.getEntries().add(rootEntry);
		final KdbxEntry groupEntry = group.getEntries().get(0);
		groupEntry.getHistory().add(new KdbxEntry());

		assertSame(group, database.getGroupByUUID(group.getUuid()));
		assertSame(subGroup, database.getGroupByUUID(subGroup.getUuid()));
		assertNull(database.getGroupByUUID(new KdbxUUID()));
		assertSame(rootEntry, database.getEntryByUUID(rootEntry.getUuid()));
		assertSame(groupEntry, database.getEntryByUUID(groupEntry.getUuid()));
		assertNull(database.getEntryByUUID(new KdbxUUID()));
		assertEquals(Arrays.asList(rootEntry.getUuid()), database.getUuidPath(rootEntry.getUuid()));
		assertNull(database.getUuidPath(new KdbxUUID()));
		assertEquals(Arrays.asList(group, subGroup), database.getAllGroups());
		assertEquals(Arrays.asList(rootEntry, groupEntry), database.getAllEntries());
		assertEquals(3, database.getAllEntriesIncludingHistory().size());
	}

	@Test
	public void testDatabaseSetters() {
		final List<KdbxGroup> groups = new ArrayList<>();
		final List<KdbxEntry> entries = new ArrayList<>();
		final KdbxMeta meta = new KdbxMeta();
		final KdbxDatabase database = new KdbxDatabase().withGroups(groups).withEntries(entries).withMeta(meta);
		assertSame(groups, database.getGroups());
		assertSame(entries, database.getEntries());
		assertSame(meta, database.getMeta());
		assertNull(database.getHeaderFormat());
		assertNull(database.getBinaryAttachments());
	}
}
