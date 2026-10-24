package de.soderer.utilities.kdbx;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import de.soderer.utilities.kdbx.KdbxTestFileBuilder.Kdbx3Defect;
import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxCustomDataItem;
import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat3;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * Tests of {@link KdbxReader} with KDBX files created by {@link KdbxTestFileBuilder}: all XML nodes, protected values, attachments,
 * the strict mode for unexpected XML nodes and the handling of invalid values.
 */
@SuppressWarnings("static-method")
public class KdbxReaderXmlTest {
	private static final KdbxCredentials CREDENTIALS = new KdbxCredentials("reader-test".toCharArray());
	private static final ZonedDateTime TIME = ZonedDateTime.of(2023, 3, 4, 5, 6, 7, 0, ZoneId.of("UTC"));
	private static final String TIME4 = KdbxTestFileBuilder.kdbx4Time(TIME);
	private static final KdbxUUID GROUP_UUID = KdbxUUID.fromHex("00112233445566778899AABBCCDDEEFF");
	private static final KdbxUUID ENTRY_UUID = KdbxUUID.fromHex("FFEEDDCCBBAA99887766554433221100");
	private static final KdbxUUID OTHER_UUID = KdbxUUID.fromHex("0123456789ABCDEF0123456789ABCDEF");
	private static final String MINIMAL_ENTRY = "<Entry><UUID>" + ENTRY_UUID.toBase64() + "</UUID><String><Key>Title</Key><Value>Entry</Value></String></Entry>";

	private static KdbxDatabase read(final byte[] data, final boolean strictMode) throws Exception {
		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(data))) {
			kdbxReader.withStrictMode(strictMode);
			return kdbxReader.readKdbxDatabase(CREDENTIALS);
		}
	}

	private static KdbxDatabase read4(final String metaContent, final String rootContent, final boolean strictMode) throws Exception {
		return read(KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml(metaContent, rootContent), CREDENTIALS), strictMode);
	}

	private static void assertTime(final ZonedDateTime expected, final ZonedDateTime actual) {
		assertTrue(expected.isEqual(actual), "Expected " + expected + " but was " + actual);
	}

	private static void assertExceptionMessage(final Exception exception, final String expectedMessagePart) {
		Throwable throwable = exception;
		while (throwable != null) {
			if (throwable.getMessage() != null && throwable.getMessage().contains(expectedMessagePart)) {
				return;
			}
			throwable = throwable.getCause();
		}
		throw new AssertionError("Expected '" + expectedMessagePart + "' in exception: " + exception, exception);
	}

	// ---- Complete data ----

	@Test
	public void testAllMetaFieldsAreRead() throws Exception {
		final byte[] icon = new byte[] { 1, 2, 3 };
		final String meta = "<Generator>Test</Generator>"
				+ "<SettingsChanged>" + TIME4 + "</SettingsChanged>"
				+ "<DatabaseName>Name</DatabaseName><DatabaseNameChanged>" + TIME4 + "</DatabaseNameChanged>"
				+ "<DatabaseDescription>Description</DatabaseDescription><DatabaseDescriptionChanged>" + TIME4 + "</DatabaseDescriptionChanged>"
				+ "<DefaultUserName>User</DefaultUserName><DefaultUserNameChanged>" + TIME4 + "</DefaultUserNameChanged>"
				+ "<MaintenanceHistoryDays>365</MaintenanceHistoryDays><Color>#FF0000</Color>"
				+ "<MasterKeyChanged>" + TIME4 + "</MasterKeyChanged><MasterKeyChangeRec>10</MasterKeyChangeRec><MasterKeyChangeForce>20</MasterKeyChangeForce>"
				+ "<MasterKeyChangeForceOnce>True</MasterKeyChangeForceOnce>"
				+ "<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>" + GROUP_UUID.toBase64() + "</RecycleBinUUID><RecycleBinChanged>" + TIME4 + "</RecycleBinChanged>"
				+ "<EntryTemplatesGroup>" + OTHER_UUID.toBase64() + "</EntryTemplatesGroup><EntryTemplatesGroupChanged>" + TIME4 + "</EntryTemplatesGroupChanged>"
				+ "<HistoryMaxItems>11</HistoryMaxItems><HistoryMaxSize>6291456</HistoryMaxSize>"
				+ "<LastSelectedGroup>" + GROUP_UUID.toBase64() + "</LastSelectedGroup><LastTopVisibleGroup>" + OTHER_UUID.toBase64() + "</LastTopVisibleGroup>"
				+ "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectUserName>True</ProtectUserName><ProtectPassword>False</ProtectPassword><ProtectURL>True</ProtectURL><ProtectNotes>True</ProtectNotes></MemoryProtection>"
				+ "<CustomData><Item><Key>PluginKey</Key><Value>PluginValue</Value><LastModificationTime>" + TIME4 + "</LastModificationTime></Item></CustomData>"
				+ "<CustomIcons><Icon><UUID>" + OTHER_UUID.toBase64() + "</UUID><Data>" + Base64.getEncoder().encodeToString(icon) + "</Data></Icon></CustomIcons>";
		final KdbxMeta kdbxMeta = read4(meta, "", true).getMeta();

		assertEquals("Test", kdbxMeta.getGenerator());
		assertTime(TIME, kdbxMeta.getSettingsChanged());
		assertEquals("Name", kdbxMeta.getDatabaseName());
		assertTime(TIME, kdbxMeta.getDatabaseNameChanged());
		assertEquals("Description", kdbxMeta.getDatabaseDescription());
		assertTime(TIME, kdbxMeta.getDatabaseDescriptionChanged());
		assertEquals("User", kdbxMeta.getDefaultUserName());
		assertTime(TIME, kdbxMeta.getDefaultUserNameChanged());
		assertEquals(365, kdbxMeta.getMaintenanceHistoryDays());
		assertEquals("#FF0000", kdbxMeta.getColor());
		assertTime(TIME, kdbxMeta.getMasterKeyChanged());
		assertEquals(10, kdbxMeta.getMasterKeyChangeRec());
		assertEquals(20, kdbxMeta.getMasterKeyChangeForce());
		assertTrue(kdbxMeta.isMasterKeyChangeForceOnce());
		assertTrue(kdbxMeta.isRecycleBinEnabled());
		assertEquals(GROUP_UUID, kdbxMeta.getRecycleBinUUID());
		assertTime(TIME, kdbxMeta.getRecycleBinChanged());
		assertEquals(OTHER_UUID, kdbxMeta.getEntryTemplatesGroup());
		assertTime(TIME, kdbxMeta.getEntryTemplatesGroupChanged());
		assertEquals(11, kdbxMeta.getHistoryMaxItems());
		assertEquals(6291456, kdbxMeta.getHistoryMaxSize());
		assertEquals(GROUP_UUID, kdbxMeta.getLastSelectedGroup());
		assertEquals(OTHER_UUID, kdbxMeta.getLastTopVisibleGroup());
		assertTrue(kdbxMeta.getMemoryProtection().isProtectTitle());
		assertTrue(kdbxMeta.getMemoryProtection().isProtectUserName());
		assertFalse(kdbxMeta.getMemoryProtection().isProtectPassword());
		assertTrue(kdbxMeta.getMemoryProtection().isProtectURL());
		assertTrue(kdbxMeta.getMemoryProtection().isProtectNotes());
		final KdbxCustomDataItem customDataItem = kdbxMeta.getCustomData().get(0);
		assertEquals("PluginKey", customDataItem.getKey());
		assertEquals("PluginValue", customDataItem.getValue());
		assertTime(TIME, customDataItem.getLastModificationTime());
		assertArrayEquals(icon, kdbxMeta.getCustomIcons().get(OTHER_UUID));
	}

	@Test
	public void testAllGroupAndEntryFieldsAreRead() throws Exception {
		final String times = "<Times><CreationTime>" + TIME4 + "</CreationTime><LastModificationTime>" + TIME4 + "</LastModificationTime>"
				+ "<LastAccessTime>" + TIME4 + "</LastAccessTime><ExpiryTime>" + TIME4 + "</ExpiryTime><Expires>True</Expires>"
				+ "<UsageCount>42</UsageCount><LocationChanged>" + TIME4 + "</LocationChanged></Times>";
		final String customData = "<CustomData><Item><Key>K</Key><Value>V</Value></Item></CustomData>";
		final String entry = "<Entry><UUID>" + ENTRY_UUID.toBase64() + "</UUID><IconID>5</IconID>"
				+ "<ForegroundColor>#000000</ForegroundColor><BackgroundColor>#FFFFFF</BackgroundColor><OverrideURL>cmd://x</OverrideURL><Tags>a;b</Tags>"
				+ times
				+ "<String><Key>Title</Key><Value>Entry title</Value></String>"
				+ "<String><Key>Password</Key><Value Protected=\"True\">{P:Secr\u00e9t}</Value></String>"
				+ "<String><Key>Empty</Key><Value/></String>"
				+ "<String><Key>Split</Key><Value>Part1<![CDATA[<Part2>]]></Value></String>"
				+ "<Binary><Key>file.txt</Key><Value Ref=\"0\"/></Binary>"
				+ "<AutoType><Enabled>True</Enabled><DataTransferObfuscation>1</DataTransferObfuscation><DefaultSequence>{USERNAME}</DefaultSequence>"
				+ "<Association><Window>Login*</Window><KeystrokeSequence>{PASSWORD}</KeystrokeSequence></Association></AutoType>"
				+ "<History><Entry><UUID>" + ENTRY_UUID.toBase64() + "</UUID><String><Key>Password</Key><Value Protected=\"True\">{P:Old}</Value></String></Entry></History>"
				+ "<CustomIconUUID>" + OTHER_UUID.toBase64() + "</CustomIconUUID>"
				+ customData
				+ "</Entry>";
		final String group = "<Group><UUID>" + GROUP_UUID.toBase64() + "</UUID><Name>Group</Name><Notes>Notes</Notes><IconID>48</IconID>"
				+ "<IsExpanded>True</IsExpanded><DefaultAutoTypeSequence>{TAB}</DefaultAutoTypeSequence>"
				+ "<EnableAutoType>False</EnableAutoType><EnableSearching>null</EnableSearching>"
				+ "<LastTopVisibleEntry>" + ENTRY_UUID.toBase64() + "</LastTopVisibleEntry>"
				+ times + entry
				+ "<Group><Name>Sub group</Name><EnableAutoType>True</EnableAutoType><EnableSearching></EnableSearching></Group>"
				+ "<CustomIconUUID>" + OTHER_UUID.toBase64() + "</CustomIconUUID>" + customData
				+ "</Group>";
		final String deletedObjects = "<DeletedObjects><DeletedObject><UUID>" + OTHER_UUID.toBase64() + "</UUID><DeletionTime>" + TIME4 + "</DeletionTime></DeletedObject></DeletedObjects>";
		final String rootEntry = "<Entry><UUID>" + OTHER_UUID.toBase64() + "</UUID><String><Key>Title</Key><Value>Root entry</Value></String></Entry>";

		final byte[] data = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml("", group + rootEntry + deletedObjects), CREDENTIALS, "attachment".getBytes(StandardCharsets.UTF_8));
		final KdbxDatabase database = read(data, true);

		final KdbxGroup kdbxGroup = database.getGroups().get(0);
		assertEquals(GROUP_UUID, kdbxGroup.getUuid());
		assertEquals("Group", kdbxGroup.getName());
		assertEquals("Notes", kdbxGroup.getNotes());
		assertEquals(48, kdbxGroup.getIconID());
		assertTrue(kdbxGroup.isExpanded());
		assertEquals("{TAB}", kdbxGroup.getDefaultAutoTypeSequence());
		assertEquals(Boolean.FALSE, kdbxGroup.getEnableAutoTypeSetting());
		assertFalse(kdbxGroup.isEnableAutoType());
		assertNull(kdbxGroup.getEnableSearchingSetting());
		assertTrue(kdbxGroup.isEnableSearching());
		assertEquals(ENTRY_UUID, kdbxGroup.getLastTopVisibleEntry());
		assertEquals(OTHER_UUID, kdbxGroup.getCustomIconUuid());
		assertEquals("V", kdbxGroup.getCustomData().get(0).getValue());
		assertTime(TIME, kdbxGroup.getTimes().getExpiryTime());
		assertTrue(kdbxGroup.getTimes().isExpires());
		assertEquals(42, kdbxGroup.getTimes().getUsageCount());
		assertTime(TIME, kdbxGroup.getTimes().getLastAccessTime());
		assertTime(TIME, kdbxGroup.getTimes().getLocationChanged());
		assertEquals(Boolean.TRUE, kdbxGroup.getGroups().get(0).getEnableAutoTypeSetting());
		assertNull(kdbxGroup.getGroups().get(0).getEnableSearchingSetting());

		final KdbxEntry kdbxEntry = kdbxGroup.getEntries().get(0);
		assertEquals(ENTRY_UUID, kdbxEntry.getUuid());
		assertEquals(5, kdbxEntry.getIconID());
		assertEquals("#000000", kdbxEntry.getForegroundColor());
		assertEquals("#FFFFFF", kdbxEntry.getBackgroundColor());
		assertEquals("cmd://x", kdbxEntry.getOverrideURL());
		assertEquals("a;b", kdbxEntry.getTags());
		assertTime(TIME, kdbxEntry.getTimes().getCreationTime());
		assertEquals("Entry title", kdbxEntry.getTitle());
		assertEquals("Secr\u00e9t", kdbxEntry.getPassword());
		assertTrue(kdbxEntry.isItemProtected("Password"));
		assertNull(kdbxEntry.getItem("Empty"));
		assertTrue(kdbxEntry.getItems().containsKey("Empty"));
		assertEquals("Part1<Part2>", kdbxEntry.getItem("Split"));
		assertEquals("attachment", new String(kdbxEntry.getBinaries().get(0).getData(), StandardCharsets.UTF_8));
		assertEquals("file.txt", kdbxEntry.getBinaries().get(0).getKey());
		assertTrue(kdbxEntry.isAutoTypeEnabled());
		assertEquals("1", kdbxEntry.getAutoTypeDataTransferObfuscation());
		assertEquals("{USERNAME}", kdbxEntry.getAutoTypeDefaultSequence());
		assertEquals("Login*", kdbxEntry.getAutoTypeAssociationWindow());
		assertEquals("{PASSWORD}", kdbxEntry.getAutoTypeAssociationKeystrokeSequence());
		assertEquals("Old", kdbxEntry.getHistory().get(0).getPassword());
		assertEquals(OTHER_UUID, kdbxEntry.getCustomIconUuid());
		assertEquals("K", kdbxEntry.getCustomData().get(0).getKey());

		assertEquals("Root entry", database.getEntries().get(0).getTitle());
		assertTime(TIME, database.getDeletedObjects().get(OTHER_UUID));
		assertEquals(3, database.getAllEntriesIncludingHistory().size());
	}

	@Test
	public void testInlineEntryBinaries() throws Exception {
		final String plainBase64 = Base64.getEncoder().encodeToString("plain".getBytes(StandardCharsets.UTF_8));
		final String compressedBase64 = Base64.getEncoder().encodeToString(Utilities.gzip("compressed".getBytes(StandardCharsets.UTF_8)));
		final String entry = "<Entry><UUID>" + ENTRY_UUID.toBase64() + "</UUID>"
				+ "<Binary><Key>plain.txt</Key><Value>" + plainBase64 + "</Value></Binary>"
				+ "<Binary><Key>compressed.txt</Key><Value Compressed=\"True\">" + compressedBase64 + "</Value></Binary>"
				+ "<Binary><Key>protected.txt</Key><Value Protected=\"True\">{P:protected}</Value></Binary>"
				+ "<Binary><Key>empty.txt</Key><Value/></Binary>"
				+ "</Entry>";
		final KdbxEntry kdbxEntry = read4("", entry, true).getEntries().get(0);
		assertEquals("plain", new String(kdbxEntry.getBinaries().get(0).getData(), StandardCharsets.UTF_8));
		assertEquals("compressed", new String(kdbxEntry.getBinaries().get(1).getData(), StandardCharsets.UTF_8));
		assertEquals("protected", new String(kdbxEntry.getBinaries().get(2).getData(), StandardCharsets.UTF_8));
		assertEquals(0, kdbxEntry.getBinaries().get(3).getData().length);
	}

	@Test
	public void testSalsa20InnerEncryptionInKdbx4() throws Exception {
		final byte[] innerStreamKey = KdbxTestFileBuilder.newInnerStreamKey();
		final byte[] innerHeader = KdbxTestFileBuilder.innerHeader(KdbxTestFileBuilder.INNER_STREAM_ID, Utilities.getLittleEndianBytes(InnerEncryptionAlgorithm.SALSA20.getId()), KdbxTestFileBuilder.INNER_STREAM_KEY, innerStreamKey);
		final String entry = "<Entry><String><Key>Password</Key><Value Protected=\"True\">{P:salsa secret}</Value></String></Entry>";
		final byte[] data = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml("", entry), CREDENTIALS, innerHeader, InnerEncryptionAlgorithm.SALSA20, innerStreamKey);
		assertEquals("salsa secret", read(data, true).getEntries().get(0).getPassword());
	}

	// ---- Strict mode ----

	/**
	 * XML parts with unexpected nodes: meta content, root content, expected error message in strict mode
	 */
	private static final String[][] UNEXPECTED_NODES = {
			{ "<Unknown/>", "", "Unexpected meta attribute node name: Unknown" },
			{ "<Binaries/>", "", "Unexpected meta binaries in data format version 4.1.0" },
			{ "<MemoryProtection><ProtectX>True</ProtectX></MemoryProtection>", "", "Unexpected meta memoryProtection node name: ProtectX" },
			{ "<CustomData><Other/></CustomData>", "", "Unexpected customData node name: Other" },
			{ "<CustomData><Item><Key>K</Key><Other/></Item></CustomData>", "", "Unexpected customData attribute node name: Other" },
			{ "<CustomIcons><Other/></CustomIcons>", "", "Unexpected custom icon node name: Other" },
			{ "", "<Other/>", "Unexpected root data node name: Other" },
			{ "", "<DeletedObjects><Other/></DeletedObjects>", "Unexpected deleted object data node name: Other" },
			{ "", "<DeletedObjects><DeletedObject><UUID>" + OTHER_UUID.toBase64() + "</UUID><DeletionTime>" + TIME4 + "</DeletionTime><Other/></DeletedObject></DeletedObjects>", "Unexpected deleted objects data node name" },
			{ "", "<Group><Other/></Group>", "Unexpected group data node name: Other" },
			{ "", "<Group><Times><Other/></Times></Group>", "Unexpected times data node name: Other" },
			{ "", "<Entry><Other/></Entry>", "Unexpected entry data node name: Other" },
			{ "", "<Entry><AutoType><Other/></AutoType></Entry>", "Unexpected autotype data node name: Other" },
			{ "", "<Entry><AutoType><Association><Other/></Association></AutoType></Entry>", "Unexpected association data node name: Other" },
			{ "", "<Entry><History><Other/></History></Entry>", "Unexpected history entry data node name: Other" },
			{ "", "<Entry><String><Key>K</Key><Other/></String></Entry>", "Unexpected key value data node name: Other" },
			{ "", "<Entry><Binary><Key>K</Key><Other/></Binary></Entry>", "Unexpected binary data node name: Other" },
	};

	@Test
	public void testUnexpectedNodesInStrictMode() throws Exception {
		for (final String[] unexpectedNode : UNEXPECTED_NODES) {
			final byte[] data = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml(unexpectedNode[0], unexpectedNode[1]), CREDENTIALS);
			final Exception exception = assertThrows(Exception.class, () -> read(data, true), unexpectedNode[2]);
			assertExceptionMessage(exception, unexpectedNode[2]);

			// Without strict mode unexpected nodes are ignored
			assertDoesNotThrow(() -> read(data, false), unexpectedNode[2]);
		}
	}

	@Test
	public void testUnexpectedRootNodeNames() throws Exception {
		final byte[] otherRoot = KdbxTestFileBuilder.buildKdbx4("<?xml version=\"1.0\"?><OtherFile><Meta/><Root/></OtherFile>", CREDENTIALS);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(otherRoot, true)), "Unexpected xml root node name: OtherFile");
		assertDoesNotThrow(() -> read(otherRoot, false));

		final byte[] otherNode = KdbxTestFileBuilder.buildKdbx4("<?xml version=\"1.0\"?><KeePassFile><Meta/><Root/><Other/></KeePassFile>", CREDENTIALS);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(otherNode, true)), "Unexpected data node name: Other");
		assertDoesNotThrow(() -> read(otherNode, false));
	}

	@Test
	public void testEntryBinaryWithReferenceAndData() throws Exception {
		final String binary = "<Binary><Key>K</Key><Value Ref=\"0\"/><Value>" + Base64.getEncoder().encodeToString(new byte[] { 1 }) + "</Value></Binary>";
		final byte[] data = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml("", "<Entry>" + binary + "</Entry>"), CREDENTIALS, new byte[] { 9 });
		assertExceptionMessage(assertThrows(Exception.class, () -> read(data, true)), "using refID and data at the same time");
		assertDoesNotThrow(() -> read(data, false));
	}

	// ---- Invalid values (also without strict mode) ----

	/**
	 * Root content with invalid values and the expected error message
	 */
	private static final String[][] INVALID_VALUES = {
			{ "<DeletedObjects><DeletedObject><DeletionTime>" + TIME4 + "</DeletionTime></DeletedObject></DeletedObjects>", "Invalid deleted object node: Missing uuid" },
			{ "<DeletedObjects><DeletedObject><UUID>" + OTHER_UUID.toBase64() + "</UUID></DeletedObject></DeletedObjects>", "Missing deletionTime" },
			{ "<Entry><String><Value>No key</Value></String></Entry>", "Invalid key value data node: Missing key" },
			{ "<Entry><Binary><Value Ref=\"0\"/></Binary></Entry>", "Invalid key value data node: Missing key" },
			{ "<Entry><IconID>abc</IconID></Entry>", "Invalid integer value: abc" },
			{ "<Entry><IconID></IconID></Entry>", "Invalid empty integer value" },
			{ "<Entry><Times><CreationTime>#no base64#</CreationTime></Times></Entry>", "Invalid DateTime base64 value" },
			{ "<Entry><Times><CreationTime>" + Base64.getEncoder().encodeToString(Utilities.getLittleEndianBytes(-1L)) + "</CreationTime></Times></Entry>", "overflowed" },
			{ "<Entry><Binary><Key>K</Key><Value Ref=\"x\"/></Binary></Entry>", "Invalid binary reference id: x" },
			{ "<Entry><Binary><Key>K</Key><Value Ref=\"5\"/></Binary></Entry>", "Cannot find referenced binary id: 5" },
			{ "<Entry><UUID>#invalid#</UUID></Entry>", "Invalid base64 string value for UUID" },
	};

	@Test
	public void testInvalidValues() throws Exception {
		for (final String[] invalidValue : INVALID_VALUES) {
			final byte[] data = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml("", invalidValue[0]), CREDENTIALS);
			assertExceptionMessage(assertThrows(Exception.class, () -> read(data, false), invalidValue[1]), invalidValue[1]);
		}
	}

	@Test
	public void testEmptyValuesAreNull() throws Exception {
		final String group = "<Group><UUID></UUID><Name/><Times><CreationTime></CreationTime><LastModificationTime/></Times></Group>";
		final KdbxGroup kdbxGroup = read4("<DatabaseName/>", group, true).getGroups().get(0);
		assertNull(kdbxGroup.getName());
		assertNull(kdbxGroup.getTimes().getCreationTime());
		assertNull(kdbxGroup.getTimes().getLastModificationTime());
		// Without UUID a new one is created
		assertTrue(kdbxGroup.getUuid() != null);
	}

	@Test
	public void testBooleanValuesAreCaseInsensitive() throws Exception {
		final KdbxGroup group = read4("", "<Group><IsExpanded> true </IsExpanded><EnableAutoType>TRUE</EnableAutoType><EnableSearching>no</EnableSearching></Group>", true).getGroups().get(0);
		assertTrue(group.isExpanded());
		assertEquals(Boolean.TRUE, group.getEnableAutoTypeSetting());
		assertEquals(Boolean.FALSE, group.getEnableSearchingSetting());
	}

	// ---- Inner header ----

	@Test
	public void testInvalidInnerHeaders() throws Exception {
		final String xml = KdbxTestFileBuilder.xml("", "");
		final byte[] key = KdbxTestFileBuilder.newInnerStreamKey();
		final byte[] chaCha20Id = Utilities.getLittleEndianBytes(InnerEncryptionAlgorithm.CHACHA20.getId());

		final byte[] missingId = KdbxTestFileBuilder.buildKdbx4(xml, CREDENTIALS, KdbxTestFileBuilder.innerHeader(KdbxTestFileBuilder.INNER_STREAM_KEY, key), InnerEncryptionAlgorithm.CHACHA20, key);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(missingId, false)), "Missing inner random stream id");

		final byte[] missingKey = KdbxTestFileBuilder.buildKdbx4(xml, CREDENTIALS, KdbxTestFileBuilder.innerHeader(KdbxTestFileBuilder.INNER_STREAM_ID, chaCha20Id), InnerEncryptionAlgorithm.CHACHA20, key);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(missingKey, false)), "Missing inner random stream key");

		final byte[] missingFlags = KdbxTestFileBuilder.buildKdbx4(xml, CREDENTIALS,
				KdbxTestFileBuilder.innerHeader(KdbxTestFileBuilder.INNER_STREAM_ID, chaCha20Id, KdbxTestFileBuilder.INNER_STREAM_KEY, key, KdbxTestFileBuilder.INNER_BINARY, new byte[0]), InnerEncryptionAlgorithm.CHACHA20, key);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(missingFlags, false)), "Missing flags byte");

		final byte[] emptyKey = KdbxTestFileBuilder.buildKdbx4(xml, CREDENTIALS, KdbxTestFileBuilder.innerHeader(KdbxTestFileBuilder.INNER_STREAM_ID, chaCha20Id, KdbxTestFileBuilder.INNER_STREAM_KEY, new byte[0]), InnerEncryptionAlgorithm.CHACHA20, key);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(emptyKey, false)), "innerEncryptionKeyBytes must not be null or empty");

		final byte[] emptySalsa20Key = KdbxTestFileBuilder.buildKdbx4(xml, CREDENTIALS,
				KdbxTestFileBuilder.innerHeader(KdbxTestFileBuilder.INNER_STREAM_ID, Utilities.getLittleEndianBytes(InnerEncryptionAlgorithm.SALSA20.getId()), KdbxTestFileBuilder.INNER_STREAM_KEY, new byte[0]), InnerEncryptionAlgorithm.SALSA20, key);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(emptySalsa20Key, false)), "innerEncryptionKeyBytes must not be null or empty");
	}

	@Test
	public void testUnsupportedInnerEncryptionAlgorithms() throws Exception {
		final String xml = KdbxTestFileBuilder.xml("", "");
		final byte[] key = KdbxTestFileBuilder.newInnerStreamKey();
		for (final InnerEncryptionAlgorithm algorithm : new InnerEncryptionAlgorithm[] { InnerEncryptionAlgorithm.NONE, InnerEncryptionAlgorithm.ARC4_VARIANT }) {
			final byte[] data = KdbxTestFileBuilder.buildKdbx4(xml, CREDENTIALS,
					KdbxTestFileBuilder.innerHeader(KdbxTestFileBuilder.INNER_STREAM_ID, Utilities.getLittleEndianBytes(algorithm.getId()), KdbxTestFileBuilder.INNER_STREAM_KEY, key), algorithm, key);
			assertThrows(Exception.class, () -> read(data, false), algorithm.name());
		}
	}

	// ---- KDBX 3 ----

	@Test
	public void testKdbx3WithMetaBinaries() throws Exception {
		final String compressedBase64 = Base64.getEncoder().encodeToString(Utilities.gzip("compressed".getBytes(StandardCharsets.UTF_8)));
		final String plainBase64 = Base64.getEncoder().encodeToString("plain".getBytes(StandardCharsets.UTF_8));
		final String meta = "<HeaderHash>{HEADERHASH}</HeaderHash><DatabaseName>V3</DatabaseName><DatabaseNameChanged>2023-03-04T05:06:07Z</DatabaseNameChanged>"
				+ "<Binaries><Binary ID=\"0\" Compressed=\"True\">" + compressedBase64 + "</Binary><Binary ID=\"1\">" + plainBase64 + "</Binary>"
				+ "<Binary ID=\"2\" Protected=\"True\">{P:protected}</Binary></Binaries>";
		final String entry = "<Entry><UUID>" + ENTRY_UUID.toBase64() + "</UUID>"
				+ "<String><Key>Password</Key><Value Protected=\"True\">{P:v3 secret}</Value></String>"
				+ "<Binary><Key>a</Key><Value Ref=\"0\"/></Binary><Binary><Key>b</Key><Value Ref=\"1\"/></Binary><Binary><Key>c</Key><Value Ref=\"2\"/></Binary></Entry>";
		final KdbxDatabase database = read(KdbxTestFileBuilder.buildKdbx3(KdbxTestFileBuilder.xml(meta, entry), CREDENTIALS, Kdbx3Defect.NONE), true);

		assertEquals("3.1.0", database.getHeaderFormat().getDataFormatVersion().toString());
		assertEquals("V3", database.getMeta().getDatabaseName());
		assertTime(TIME, database.getMeta().getDatabaseNameChanged());
		final KdbxEntry entry1 = database.getEntries().get(0);
		assertEquals("v3 secret", entry1.getPassword());
		assertEquals("compressed", new String(entry1.getBinaries().get(0).getData(), StandardCharsets.UTF_8));
		assertEquals("plain", new String(entry1.getBinaries().get(1).getData(), StandardCharsets.UTF_8));
		assertEquals("protected", new String(entry1.getBinaries().get(2).getData(), StandardCharsets.UTF_8));
	}

	@Test
	public void testKdbx3HeaderHash() throws Exception {
		// Older KDBX 3 files have no header hash, which is only accepted without strict mode
		final byte[] withoutHash = KdbxTestFileBuilder.buildKdbx3(KdbxTestFileBuilder.xml("", MINIMAL_ENTRY), CREDENTIALS, Kdbx3Defect.NONE);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(withoutHash, true)), "Missing header hash");
		assertEquals("Entry", read(withoutHash, false).getEntries().get(0).getTitle());

		final String wrongHash = Base64.getEncoder().encodeToString(new byte[32]);
		final byte[] withWrongHash = KdbxTestFileBuilder.buildKdbx3(KdbxTestFileBuilder.xml("<HeaderHash>" + wrongHash + "</HeaderHash>", ""), CREDENTIALS, Kdbx3Defect.NONE);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(withWrongHash, false)), "Outer header data corrupted");
	}

	@Test
	public void testKdbx3PayloadDefects() throws Exception {
		final String xml = KdbxTestFileBuilder.xml("<HeaderHash>{HEADERHASH}</HeaderHash>", "");
		final byte[] wrongBlockIndex = KdbxTestFileBuilder.buildKdbx3(xml, CREDENTIALS, Kdbx3Defect.WRONG_BLOCK_INDEX);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(wrongBlockIndex, false)), "Invalid payload block index 1, expected 0");

		final byte[] wrongStartBytes = KdbxTestFileBuilder.buildKdbx3(xml, CREDENTIALS, Kdbx3Defect.WRONG_STREAM_START_BYTES);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(wrongStartBytes, false)), "Maybe the given credentials are wrong");
	}

	@Test
	public void testKdbx3ShortPayload() throws Exception {
		final byte[] data = KdbxTestFileBuilder.buildKdbx3(KdbxTestFileBuilder.xml("", ""), CREDENTIALS, Kdbx3Defect.SHORT_PAYLOAD);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(data, false)), "Cannot read start bytes from payload");
	}

	@Test
	public void testUnsupportedOuterEncryptionAlgorithms() throws Exception {
		final String xml = KdbxTestFileBuilder.xml("", "");
		final byte[] kdbx3 = KdbxTestFileBuilder.buildKdbx3(new KdbxHeaderFormat3().withTransformRounds(10).withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.TWOFISH), xml, CREDENTIALS, Kdbx3Defect.NONE);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(kdbx3, false)), "Cipher TWOFISH is not implemented yet");

		final byte[] key = KdbxTestFileBuilder.newInnerStreamKey();
		final byte[] kdbx4 = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.createHeader4().withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.TWOFISH), xml, CREDENTIALS,
				KdbxTestFileBuilder.standardInnerHeader(key), InnerEncryptionAlgorithm.CHACHA20, key);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(kdbx4, false)), "Cipher TWOFISH is not implemented yet");
	}

	@Test
	public void testKdbx3StrictModeAndInvalidBinaryId() throws Exception {
		final byte[] unexpectedBinaryNode = KdbxTestFileBuilder.buildKdbx3(KdbxTestFileBuilder.xml("<HeaderHash>{HEADERHASH}</HeaderHash><Binaries><Other/></Binaries>", ""), CREDENTIALS, Kdbx3Defect.NONE);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(unexpectedBinaryNode, true)), "Unexpected binary node name: Other");
		assertDoesNotThrow(() -> read(unexpectedBinaryNode, false));

		final byte[] invalidBinaryId = KdbxTestFileBuilder.buildKdbx3(KdbxTestFileBuilder.xml("<Binaries><Binary ID=\"x\">AAAA</Binary></Binaries>", ""), CREDENTIALS, Kdbx3Defect.NONE);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(invalidBinaryId, false)), "Invalid binary id: x");

		final byte[] otherRoot = KdbxTestFileBuilder.buildKdbx3("<?xml version=\"1.0\"?><OtherFile><Meta><HeaderHash>{HEADERHASH}</HeaderHash></Meta><Other/></OtherFile>", CREDENTIALS, Kdbx3Defect.NONE);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(otherRoot, true)), "Unexpected xml root node name");
		assertDoesNotThrow(() -> read(otherRoot, false));

		final byte[] otherNode = KdbxTestFileBuilder.buildKdbx3("<?xml version=\"1.0\"?><KeePassFile><Meta><HeaderHash>{HEADERHASH}</HeaderHash></Meta><Other/></KeePassFile>", CREDENTIALS, Kdbx3Defect.NONE);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(otherNode, true)), "Unexpected data node name: Other");
	}

	// ---- Outer format errors ----

	@Test
	public void testWrongCredentials() throws Exception {
		final byte[] kdbx4 = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml("", ""), CREDENTIALS);
		final byte[] kdbx3 = KdbxTestFileBuilder.buildKdbx3(KdbxTestFileBuilder.xml("", ""), CREDENTIALS, Kdbx3Defect.NONE);
		for (final byte[] data : new byte[][] { kdbx4, kdbx3 }) {
			try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(data))) {
				final Exception exception = assertThrows(Exception.class, () -> kdbxReader.readKdbxDatabase("wrong".toCharArray()));
				assertExceptionMessage(exception, "Maybe the given credentials are wrong");
			}
		}
	}

	@Test
	public void testCorruptedOuterHeader() throws Exception {
		final byte[] data = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml("", ""), CREDENTIALS);
		final int headerLength = de.soderer.utilities.kdbx.data.KdbxHeaderFormat4.read(new ByteArrayInputStream(data)).getHeaderBytes().length;
		// Change the last byte of the header end marker, which is not interpreted, but covered by the header hash
		data[headerLength - 1] ^= 0x01;
		assertExceptionMessage(assertThrows(Exception.class, () -> read(data, false)), "Outer header data corrupted");
	}

	@Test
	public void testTruncatedKdbx4Headers() throws Exception {
		final byte[] data = KdbxTestFileBuilder.buildKdbx4(KdbxTestFileBuilder.xml("", ""), CREDENTIALS);
		final int headerLength = de.soderer.utilities.kdbx.data.KdbxHeaderFormat4.read(new ByteArrayInputStream(data)).getHeaderBytes().length;
		final byte[] withoutHash = java.util.Arrays.copyOf(data, headerLength + 10);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(withoutHash, false)), "Cannot read header SHA-256 hash bytes");
		final byte[] withoutHmac = java.util.Arrays.copyOf(data, headerLength + 32 + 10);
		assertExceptionMessage(assertThrows(Exception.class, () -> read(withoutHmac, false)), "Cannot read HMAC code bytes");
	}

	@Test
	public void testUnsupportedFileVersions() throws Exception {
		final byte[] magic = Utilities.getLittleEndianBytes(0x9AA2D903);
		final byte[] keePass2 = Utilities.getLittleEndianBytes(0xB54BFB67);

		final byte[] majorVersion5 = Utilities.concatArrays(Utilities.concatArrays(magic, keePass2), new byte[] { 0, 0, 5, 0 });
		assertExceptionMessage(assertThrows(Exception.class, () -> read(majorVersion5, false)), "Major kdbx file data format version 5 is not supported");

		final byte[] keePass1 = Utilities.concatArrays(Utilities.concatArrays(magic, Utilities.getLittleEndianBytes(0xB54BFB65)), new byte[] { 0, 0, 4, 0 });
		assertExceptionMessage(assertThrows(Exception.class, () -> read(keePass1, false)), "Unsupported kdbx version: KEEPASS1");

		final byte[] unknownSignature = Utilities.concatArrays(Utilities.concatArrays(magic, Utilities.getLittleEndianBytes(0x12345678)), new byte[] { 0, 0, 4, 0 });
		assertExceptionMessage(assertThrows(Exception.class, () -> read(unknownSignature, false)), "Invalid kdbx version");

		assertExceptionMessage(assertThrows(Exception.class, () -> read("Not a KDBX file".getBytes(StandardCharsets.UTF_8), false)), "Invalid magic number");
		assertExceptionMessage(assertThrows(Exception.class, () -> read(new byte[0], false)), "Cannot read kdbx magic number");
		assertExceptionMessage(assertThrows(Exception.class, () -> read(magic, false)), "Cannot read kdbx version number");
		assertExceptionMessage(assertThrows(Exception.class, () -> read(Utilities.concatArrays(magic, keePass2), false)), "Cannot read kdbx data format version");
	}

	@Test
	public void testReaderSettings() throws Exception {
		try (KdbxReader kdbxReader = new KdbxReader(null)) {
			assertFalse(kdbxReader.isStrictMode());
			assertTrue(kdbxReader.withStrictMode(true).isStrictMode());
		}
	}
}
