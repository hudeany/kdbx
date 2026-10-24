package de.soderer.utilities.kdbx.data;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
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
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxStandardIcon;
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxVersion;
import de.soderer.utilities.kdbx.data.KdbxConstants.KeyDerivationFunction;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;

/**
 * Tests of the data classes: entries, groups, UUIDs, times, attachments and constants.
 */
@SuppressWarnings("static-method")
public class KdbxDataClassesTest {
	private static final ZonedDateTime TIME = ZonedDateTime.of(2024, 1, 2, 3, 4, 5, 0, ZoneId.of("UTC"));

	// ---- KdbxEntry ----

	private static KdbxEntry createFullEntry(final KdbxUUID uuid, final KdbxTimes times) {
		return new KdbxEntry().withUuid(uuid).withTitle("Title").withUsername("User").withPassword("Secret").withUrl("https://example.com").withNotes("Notes")
				.withIconID(5).withCustomIconUuid(KdbxUUID.fromHex("0123456789ABCDEF0123456789ABCDEF")).withForegroundColor("#000000").withBackgroundColor("#FFFFFF")
				.withOverrideURL("cmd://open").withTags("tag1;tag2").withTimes(times).withItem("Custom", "Value")
				.withAutoType(true, "1", "{USERNAME}", "Window", "{PASSWORD}").withCustomData(new ArrayList<>(Arrays.asList(new KdbxCustomDataItem().withKey("K"))));
	}

	@Test
	public void testEntryStandardItems() {
		final KdbxEntry entry = createFullEntry(new KdbxUUID(), new KdbxTimes());
		assertEquals("Title", entry.getItem("Title"));
		assertEquals("User", entry.getUsername());
		assertEquals("https://example.com", entry.getUrl());
		assertEquals("Notes", entry.getNotes());
		assertEquals("Value", entry.getItem("Custom"));
		assertNull(entry.getItem("Missing"));
		// Items with other types are returned as text
		entry.setItem("Number", 42);
		assertEquals("42", entry.getItem("Number"));
		assertEquals(Integer.valueOf(42), entry.getItems().get("Number"));
	}

	@Test
	public void testEntryUuidIsCreatedOnFirstAccess() {
		final KdbxEntry entry = new KdbxEntry();
		final KdbxUUID uuid = entry.getUuid();
		assertSame(uuid, entry.getUuid());
		assertNotEquals(uuid, new KdbxEntry().getUuid());
	}

	@Test
	public void testEntryProtectedItems() {
		final KdbxEntry entry = new KdbxEntry().withItemProtected("PIN", true).withItemProtected("Other", true);
		assertTrue(entry.isItemProtected("PIN"));
		entry.setItemProtected("Other", false);
		assertFalse(entry.isItemProtected("Other"));
		assertEquals(Collections.singleton("PIN"), entry.getProtectedItemKeys());
		assertThrows(UnsupportedOperationException.class, () -> entry.getProtectedItemKeys().add("X"));
	}

	@Test
	public void testEntryTimesMustNotBeNull() {
		assertThrows(IllegalArgumentException.class, () -> new KdbxEntry().setTimes(null));
		assertThrows(IllegalArgumentException.class, () -> new KdbxGroup().setTimes(null));
	}

	@Test
	public void testEntryEqualsAndHashCode() {
		final KdbxUUID uuid = new KdbxUUID();
		final KdbxTimes times = new KdbxTimes().withCreationTime(TIME).withLastModificationTime(TIME);
		final KdbxEntry entry1 = createFullEntry(uuid, times);
		// Custom data items have no equals method, so the same list instance is used
		final KdbxEntry entry2 = createFullEntry(uuid, times).withCustomData(entry1.getCustomData());

		assertEquals(entry1, entry1);
		assertEquals(entry1, entry2);
		assertEquals(entry1.hashCode(), entry2.hashCode());
		assertNotEquals(entry1, null);
		assertNotEquals(entry1, "Title");

		// Each difference makes the entries unequal
		final List<KdbxEntry> changedEntries = new ArrayList<>();
		changedEntries.add(createFullEntry(uuid, times).withCustomData(entry1.getCustomData()).withPassword("Other"));
		changedEntries.add(createFullEntry(new KdbxUUID(), times).withCustomData(entry1.getCustomData()));
		changedEntries.add(createFullEntry(uuid, new KdbxTimes().withCreationTime(TIME.plusDays(1))).withCustomData(entry1.getCustomData()));
		changedEntries.add(createFullEntry(uuid, times).withCustomData(entry1.getCustomData()).withIconID(6));
		changedEntries.add(createFullEntry(uuid, times).withCustomData(entry1.getCustomData()).withTags("other"));
		changedEntries.add(createFullEntry(uuid, times).withCustomData(entry1.getCustomData()).withAutoType(false, "1", "{USERNAME}", "Window", "{PASSWORD}"));
		changedEntries.add(createFullEntry(uuid, times).withCustomData(entry1.getCustomData()).withItemProtected("Custom", true));
		final KdbxEntry entryWithHistory = createFullEntry(uuid, times).withCustomData(entry1.getCustomData());
		entryWithHistory.getHistory().add(new KdbxEntry());
		changedEntries.add(entryWithHistory);
		for (final KdbxEntry changedEntry : changedEntries) {
			assertNotEquals(entry1, changedEntry);
		}
	}

	@Test
	public void testEntryToStringHidesPassword() {
		final KdbxEntry entry = createFullEntry(KdbxUUID.fromHex("00000000000000000000000000000001"), new KdbxTimes().withCreationTime(TIME).withLastModificationTime(TIME));
		entry.getHistory().add(new KdbxEntry());
		entry.getBinaries().add(new KdbxEntryBinary().withKey("a.txt"));

		final String text = entry.toString();
		assertTrue(text.startsWith("UUID: 00000000000000000000000000000001\n"));
		assertTrue(text.contains("Password: ***\n"));
		assertFalse(text.contains("Secret"));
		for (final String expectedLine : new String[] { "Title: Title", "Username: User", "URL: https://example.com", "Notes: Notes", "Created: ", "Changed: ", "Custom: Value",
				"IconID: 5", "CustomIconUuid: 0123456789ABCDEF0123456789ABCDEF", "ForegroundColor: #000000", "BackgroundColor: #FFFFFF", "OverrideURL: cmd://open", "Tags: tag1;tag2",
				"AutoTypeEnabled: true", "AutoTypeDataTransferObfuscation: 1", "AutoTypeDefaultSequence: {USERNAME}", "AutoTypeAssociationWindow: Window",
				"AutoTypeAssociationKeystrokeSequence: {PASSWORD}", "CustomData size: 1", "History size: 1", "Binaries size: 1" }) {
			assertTrue(text.contains(expectedLine + (expectedLine.endsWith(": ") ? "" : "\n")), "Missing: " + expectedLine);
		}

		assertTrue(entry.toString(true).contains("Password: Secret\n"));
	}

	@Test
	public void testToStringOfEmptyEntry() {
		final KdbxEntry entry = new KdbxEntry().withIconID(0);
		entry.getTimes().setCreationTime(null);
		entry.getTimes().setLastModificationTime(null);
		// The UUID is only created on first access
		assertEquals("UUID: null\n", entry.toString());
	}

	// ---- KdbxGroup ----

	@Test
	public void testGroupLookups() {
		final KdbxGroup root = new KdbxGroup().withName("Root");
		final KdbxGroup sub1 = new KdbxGroup().withName("Sub1");
		final KdbxGroup sub2 = new KdbxGroup().withName("Sub2");
		final KdbxGroup subSub = new KdbxGroup().withName("SubSub");
		final KdbxEntry rootEntry = new KdbxEntry().withTitle("RootEntry");
		final KdbxEntry deepEntry = new KdbxEntry().withTitle("DeepEntry");
		root.getGroups().add(sub1);
		root.getGroups().add(sub2);
		sub2.getGroups().add(subSub);
		root.getEntries().add(rootEntry);
		subSub.getEntries().add(deepEntry);

		assertSame(sub2, root.getGroupByUUID(sub2.getUuid()));
		assertSame(subSub, root.getGroupByUUID(subSub.getUuid()));
		assertNull(root.getGroupByUUID(root.getUuid()));
		assertNull(root.getGroupByUUID(new KdbxUUID()));

		assertSame(rootEntry, root.getEntryByUUID(rootEntry.getUuid()));
		assertSame(deepEntry, root.getEntryByUUID(deepEntry.getUuid()));
		assertNull(root.getEntryByUUID(new KdbxUUID()));

		assertEquals(Arrays.asList(root.getUuid()), root.getUuidPath(root.getUuid()));
		assertEquals(Arrays.asList(root.getUuid(), rootEntry.getUuid()), root.getUuidPath(rootEntry.getUuid()));
		assertEquals(Arrays.asList(root.getUuid(), sub2.getUuid(), subSub.getUuid(), deepEntry.getUuid()), root.getUuidPath(deepEntry.getUuid()));
		assertNull(root.getUuidPath(new KdbxUUID()));

		assertEquals(Arrays.asList(sub1, sub2, subSub), root.getAllGroups());
		assertEquals(Arrays.asList(rootEntry, deepEntry), root.getAllEntries());
	}

	@Test
	public void testGroupInheritedSettings() {
		final KdbxGroup group = new KdbxGroup();
		// "null" means inherit from the parent group, which enables the setting by default
		assertNull(group.getEnableAutoTypeSetting());
		assertTrue(group.isEnableAutoType());
		assertTrue(group.isEnableSearching());

		group.setEnableAutoType(false);
		group.setEnableSearching(false);
		assertEquals(Boolean.FALSE, group.getEnableAutoTypeSetting());
		assertFalse(group.isEnableAutoType());
		assertFalse(group.isEnableSearching());

		group.setEnableAutoTypeSetting(null);
		group.setEnableSearchingSetting(Boolean.TRUE);
		assertTrue(group.isEnableAutoType());
		assertTrue(group.isEnableSearching());
	}

	@Test
	public void testGroupLists() {
		final List<KdbxGroup> groups = new ArrayList<>();
		final List<KdbxEntry> entries = new ArrayList<>();
		final KdbxGroup group = new KdbxGroup().withGroups(groups).withEntries(entries);
		assertSame(groups, group.getGroups());
		assertSame(entries, group.getEntries());
	}

	// ---- KdbxUUID ----

	@Test
	public void testUuidConversions() {
		final KdbxUUID uuid = KdbxUUID.fromHex("00112233445566778899AABBCCDDEEFF");
		assertEquals("00112233445566778899AABBCCDDEEFF", uuid.toHex());
		assertEquals(uuid.toHex(), uuid.toString());
		assertEquals("ABEiM0RVZneImaq7zN3u/w==", uuid.toBase64());
		assertEquals(uuid, KdbxUUID.fromBase64(uuid.toBase64()));
		assertEquals(uuid, KdbxUUID.fromHex("0x00112233445566778899aabbccddeeff"));
		assertEquals(uuid.hashCode(), KdbxUUID.fromBase64(uuid.toBase64()).hashCode());
		assertNull(KdbxUUID.fromBase64(null));
		assertNull(KdbxUUID.fromBase64("  "));
		assertNotEquals(uuid, "00112233445566778899AABBCCDDEEFF");
	}

	@Test
	public void testUuidCopiesData() {
		final byte[] data = new byte[16];
		final KdbxUUID uuid = new KdbxUUID(data);
		data[0] = 1;
		assertEquals("00000000000000000000000000000000", uuid.toHex());
	}

	@Test
	public void testInvalidUuids() {
		assertThrows(IllegalArgumentException.class, () -> new KdbxUUID(null));
		assertThrows(IllegalArgumentException.class, () -> new KdbxUUID(new byte[15]));
		assertThrows(IllegalArgumentException.class, () -> KdbxUUID.fromHex("0011"));
		assertThrows(IllegalArgumentException.class, () -> KdbxUUID.fromHex("XX112233445566778899AABBCCDDEEFF"));
		assertThrows(IllegalArgumentException.class, () -> KdbxUUID.fromBase64("AAAA"));
		assertThrows(IllegalArgumentException.class, () -> KdbxUUID.fromBase64("#no base64#"));
	}

	@Test
	public void testRandomUuidsDiffer() {
		assertNotEquals(new KdbxUUID(), new KdbxUUID());
	}

	// ---- KdbxTimes ----

	@Test
	public void testNewTimesHaveCreationTime() {
		final KdbxTimes times = new KdbxTimes();
		assertTrue(times.getCreationTime() != null);
		assertEquals(times.getCreationTime(), times.getLastModificationTime());
		assertFalse(times.isExpires());
		assertEquals(0, times.getUsageCount());
	}

	@Test
	public void testTimesEquals() {
		final KdbxTimes times1 = new KdbxTimes().withCreationTime(TIME).withLastModificationTime(TIME).withLastAccessTime(TIME).withExpiryTime(TIME).withLocationChanged(TIME).withExpires(true).withUsageCount(2);
		final KdbxTimes times2 = new KdbxTimes().withCreationTime(TIME).withLastModificationTime(TIME).withLastAccessTime(TIME).withExpiryTime(TIME).withLocationChanged(TIME).withExpires(true).withUsageCount(2);
		assertEquals(times1, times1);
		assertEquals(times1, times2);
		assertEquals(times1.hashCode(), times2.hashCode());
		assertNotEquals(times1, null);
		assertNotEquals(times1, TIME);
		assertNotEquals(times1, times2.withUsageCount(3));
		assertNotEquals(times1, times2.withUsageCount(2).withExpires(false));
		assertNotEquals(times1, times2.withExpires(true).withLastAccessTime(null));
		assertNotEquals(new KdbxTimes().withLastAccessTime(null), new KdbxTimes().withLastAccessTime(TIME));
		assertEquals(new KdbxTimes().withCreationTime(null).withLastModificationTime(null), new KdbxTimes().withCreationTime(null).withLastModificationTime(null));
	}

	// ---- Attachments and custom data ----

	@Test
	public void testEntryBinaryCompressesData() throws Exception {
		final byte[] data = "attachment data".getBytes(StandardCharsets.UTF_8);
		final KdbxEntryBinary binary = new KdbxEntryBinary().withKey("a.txt").withRefId(3).withData(data);
		assertEquals("a.txt", binary.getKey());
		assertEquals(Integer.valueOf(3), binary.getRefId());
		assertArrayEquals(data, binary.getData());

		binary.setData(null);
		assertNull(binary.getData());
		assertNull(new KdbxEntryBinary().getData());

		final KdbxEntryBinary invalidBinary = new KdbxEntryBinary().withCompressedData(new byte[] { 1, 2, 3 });
		assertThrows(Exception.class, invalidBinary::getData);
	}

	@Test
	public void testCustomDataItem() {
		final KdbxCustomDataItem item = new KdbxCustomDataItem().withKey("Key").withValue("Value").withLastModificationTime(TIME);
		assertEquals("Key", item.getKey());
		assertEquals("Value", item.getValue());
		assertEquals(TIME, item.getLastModificationTime());
		assertNull(new KdbxCustomDataItem().getLastModificationTime());
	}

	@Test
	public void testMemoryProtectionDefaults() {
		final KdbxMemoryProtection memoryProtection = new KdbxMemoryProtection();
		assertFalse(memoryProtection.isProtectTitle());
		assertFalse(memoryProtection.isProtectUserName());
		assertTrue(memoryProtection.isProtectPassword());
		assertFalse(memoryProtection.isProtectURL());
		assertFalse(memoryProtection.isProtectNotes());
	}

	@Test
	public void testMetaDefaults() {
		final KdbxMeta meta = new KdbxMeta();
		// The memory protection is created on first access
		assertSame(meta.getMemoryProtection(), meta.getMemoryProtection());
		assertTrue(meta.getCustomIcons().isEmpty());
		assertNull(meta.getCustomData());
		final Map<KdbxUUID, byte[]> customIcons = new LinkedHashMap<>();
		assertSame(customIcons, meta.withCustomIcons(customIcons).getCustomIcons());
	}

	@Test
	public void testRecycleBinUuidIsCreatedWhenEnabled() {
		final KdbxMeta meta = new KdbxMeta();
		meta.setRecycleBinEnabled(false);
		assertNull(meta.getRecycleBinUUID());
		meta.setRecycleBinEnabled(true);
		final KdbxUUID recycleBinUuid = meta.getRecycleBinUUID();
		assertTrue(recycleBinUuid != null);
		// An existing UUID is kept
		meta.setRecycleBinEnabled(true);
		assertSame(recycleBinUuid, meta.getRecycleBinUUID());
	}

	@Test
	public void testDatabaseMetaMustNotBeNull() {
		assertThrows(IllegalArgumentException.class, () -> new de.soderer.utilities.kdbx.KdbxDatabase().setMeta(null));
	}

	// ---- Constants ----

	@Test
	public void testConstantsUtilityClass() throws Exception {
		final Constructor<KdbxConstants> constructor = KdbxConstants.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		final InvocationTargetException exception = assertThrows(InvocationTargetException.class, constructor::newInstance);
		assertTrue(exception.getCause() instanceof IllegalStateException);
	}

	@Test
	public void testConstantLookupsById() throws Exception {
		for (final KdbxVersion version : KdbxVersion.values()) {
			assertSame(version, KdbxVersion.getById(version.getVersionId()));
		}
		assertFalse(KdbxVersion.KEEPASS1.isKeepass2());
		assertTrue(KdbxVersion.KEEPASS2_PRERELEASE.isKeepass2());
		for (final KeyDerivationFunction keyDerivationFunction : KeyDerivationFunction.values()) {
			assertSame(keyDerivationFunction, KeyDerivationFunction.getById(keyDerivationFunction.getId()));
		}
		for (final OuterEncryptionAlgorithm outerEncryptionAlgorithm : OuterEncryptionAlgorithm.values()) {
			assertSame(outerEncryptionAlgorithm, OuterEncryptionAlgorithm.getById(outerEncryptionAlgorithm.getId()));
		}
		for (final InnerEncryptionAlgorithm innerEncryptionAlgorithm : InnerEncryptionAlgorithm.values()) {
			assertSame(innerEncryptionAlgorithm, InnerEncryptionAlgorithm.getById(innerEncryptionAlgorithm.getId()));
		}
		for (final KdbxStandardIcon icon : KdbxStandardIcon.values()) {
			assertSame(icon, KdbxStandardIcon.getById(icon.getId()));
		}
		assertEquals(69, KdbxStandardIcon.values().length);
		assertEquals(68, KdbxStandardIcon.A_MOBILE_DEVICE.getId());
	}

	@Test
	public void testInvalidConstantIds() {
		assertTrue(assertThrows(Exception.class, () -> KdbxVersion.getById(0x12345678)).getMessage().contains("0x12345678"));
		assertThrows(Exception.class, () -> KeyDerivationFunction.getById(new byte[16]));
		assertThrows(Exception.class, () -> OuterEncryptionAlgorithm.getById(new byte[16]));
		assertThrows(Exception.class, () -> InnerEncryptionAlgorithm.getById(99));
		assertThrows(Exception.class, () -> KdbxStandardIcon.getById(69));
		assertThrows(Exception.class, () -> KdbxStandardIcon.getById(-1));
	}

	@Test
	public void testBinary() {
		final byte[] data = new byte[] { 1, 2 };
		final KdbxBinary binary = new KdbxBinary().withId(4).withCompressed(true).withData(data);
		assertEquals(4, binary.getId());
		assertTrue(binary.isCompressed());
		assertSame(data, binary.getData());
	}
}
