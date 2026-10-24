package de.soderer.utilities.kdbx.utilities;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Random;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Tests of {@link Utilities}, {@link Version}, {@link VariantDictionary} and the type length value structures.
 */
@SuppressWarnings("static-method")
public class KdbxUtilitiesTest {
	@Test
	public void testUtilityClass() throws Exception {
		final Constructor<Utilities> constructor = Utilities.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertTrue(assertThrows(InvocationTargetException.class, constructor::newInstance).getCause() instanceof IllegalStateException);
	}

	// ---- Strings and hex ----

	@Test
	public void testBlankChecks() {
		assertTrue(Utilities.isBlank(null));
		assertTrue(Utilities.isBlank(""));
		assertTrue(Utilities.isBlank(" \t"));
		assertFalse(Utilities.isBlank("x"));
		assertTrue(Utilities.isNotBlank(" x "));
	}

	@Test
	public void testHexConversions() {
		assertEquals("00_7F_80_FF", Utilities.toHexString(new byte[] { 0, 0x7F, (byte) 0x80, (byte) 0xFF }));
		assertEquals("0A0B", Utilities.toHexString(new byte[] { 10, 11 }, ""));
		assertEquals("<empty>", Utilities.toHexString(null, ""));
		assertEquals("<empty>", Utilities.toHexString(new byte[0]));

		assertArrayEquals(new byte[] { 0, 0x7F, (byte) 0x80, (byte) 0xFF }, Utilities.fromHexString("007F80ff"));
		assertArrayEquals(new byte[] { 0x12 }, Utilities.fromHexString("0X12"));
		assertArrayEquals(new byte[0], Utilities.fromHexString(""));
		assertNull(Utilities.fromHexString(null));
		assertNull(Utilities.fromHexString(null, true));
		assertThrows(RuntimeException.class, () -> Utilities.fromHexString("123"));
		assertThrows(RuntimeException.class, () -> Utilities.fromHexString("12G4"));

		// Separators like in UUID notation are ignored on request
		assertArrayEquals(new byte[] { 0x61, (byte) 0xAB, 0x05 }, Utilities.fromHexString("61AB-05", true));
		assertThrows(RuntimeException.class, () -> Utilities.fromHexString("61AB-05", false));
		assertArrayEquals(new byte[] { 0x61, (byte) 0xAB }, Utilities.fromHexString("61AB", false));
	}

	// ---- Streams ----

	@Test
	public void testStreamHelpers() throws Exception {
		assertNull(Utilities.toByteArray(null));
		final byte[] data = new byte[10000];
		new Random(1).nextBytes(data);
		assertArrayEquals(data, Utilities.toByteArray(new ByteArrayInputStream(data)));
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		assertEquals(data.length, Utilities.copy(new ByteArrayInputStream(data), outputStream));
		assertArrayEquals(data, outputStream.toByteArray());
	}

	@Test
	public void testReadLittleEndianValuesFromStream() throws Exception {
		assertEquals(0x04030201, Utilities.readLittleEndianIntFromStream(new ByteArrayInputStream(new byte[] { 1, 2, 3, 4 })));
		assertEquals((short) 0x0201, Utilities.readLittleEndianShortFromStream(new ByteArrayInputStream(new byte[] { 1, 2 })));

		assertTrue(assertThrows(Exception.class, () -> Utilities.readLittleEndianIntFromStream(new ByteArrayInputStream(new byte[0]))).getMessage().contains("End of stream"));
		assertTrue(assertThrows(Exception.class, () -> Utilities.readLittleEndianIntFromStream(new ByteArrayInputStream(new byte[3]))).getMessage().contains("Not enough data left"));
		assertTrue(assertThrows(Exception.class, () -> Utilities.readLittleEndianShortFromStream(new ByteArrayInputStream(new byte[0]))).getMessage().contains("End of stream"));
		assertTrue(assertThrows(Exception.class, () -> Utilities.readLittleEndianShortFromStream(new ByteArrayInputStream(new byte[1]))).getMessage().contains("Not enough data left"));

		assertArrayEquals(new byte[] { 1, 2 }, Utilities.readFully(new ByteArrayInputStream(new byte[] { 1, 2, 3 }), 2, "test data"));
		final EOFException exception = assertThrows(EOFException.class, () -> Utilities.readFully(new ByteArrayInputStream(new byte[] { 1 }), 2, "test data"));
		assertTrue(exception.getMessage().contains("Cannot read test data: premature end of stream after 1 of 2 bytes"));
	}

	@Test
	public void testLittleEndianByteArrays() {
		assertEquals(-1, Utilities.readLittleEndianValueFromByteArray(new byte[] { (byte) 0xFF }));
		assertEquals(0x0201, Utilities.readLittleEndianValueFromByteArray(new byte[] { 1, 2 }));
		assertEquals(0x04030201, Utilities.readLittleEndianValueFromByteArray(new byte[] { 1, 2, 3, 4 }));
		assertEquals(0x0807060504030201L, Utilities.readLittleEndianValueFromByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }));
		assertThrows(RuntimeException.class, () -> Utilities.readLittleEndianValueFromByteArray(new byte[3]));

		assertArrayEquals(new byte[] { 1, 2 }, Utilities.getLittleEndianBytes((short) 0x0201));
		assertArrayEquals(new byte[] { 1, 2, 3, 4 }, Utilities.getLittleEndianBytes(0x04030201));
		assertArrayEquals(new byte[] { 1, 0, 0, 0, 0, 0, 0, (byte) 0x80 }, Utilities.getLittleEndianBytes(0x8000000000000001L));

		assertEquals(0x04030201, Utilities.readIntFromLittleEndianBytes(new byte[] { 1, 2, 3, 4 }));
		assertThrows(RuntimeException.class, () -> Utilities.readIntFromLittleEndianBytes(new byte[8]));
		assertThrows(RuntimeException.class, () -> Utilities.readIntFromLittleEndianBytes(null));
		assertEquals(Long.MIN_VALUE, Utilities.readLongFromLittleEndianBytes(Utilities.getLittleEndianBytes(Long.MIN_VALUE)));
		assertThrows(RuntimeException.class, () -> Utilities.readLongFromLittleEndianBytes(new byte[4]));
		assertThrows(RuntimeException.class, () -> Utilities.readLongFromLittleEndianBytes(null));
	}

	@Test
	public void testByteHelpers() {
		assertArrayEquals("\u00c4bc".getBytes(StandardCharsets.UTF_8), Utilities.toBytes("\u00c4bc".toCharArray()));
		assertArrayEquals(new byte[0], Utilities.toBytes(new char[0]));
		assertArrayEquals(new byte[] { 1, 2, 3 }, Utilities.concatArrays(new byte[] { 1 }, new byte[] { 2, 3 }));
		assertArrayEquals(new byte[0], Utilities.concatArrays(new byte[0], new byte[0]));
	}

	@Test
	public void testDeriveKeyByAes() {
		final byte[] salt = new byte[32];
		final byte[] key = new byte[16];
		key[0] = 1;
		// Zero rounds return a copy of the key
		final byte[] unchanged = Utilities.deriveKeyByAES(salt, 0, key);
		assertArrayEquals(key, unchanged);
		assertNotEquals(System.identityHashCode(key), System.identityHashCode(unchanged));
		// Rounds are applied one after another
		assertArrayEquals(Utilities.deriveKeyByAES(salt, 2, key), Utilities.deriveKeyByAES(salt, 1, Utilities.deriveKeyByAES(salt, 1, key)));
		// An invalid AES key length
		assertThrows(RuntimeException.class, () -> Utilities.deriveKeyByAES(new byte[5], 1, key));
	}

	@Test
	public void testGzip() throws Exception {
		final byte[] data = "compress me compress me compress me".getBytes(StandardCharsets.UTF_8);
		final byte[] compressedData = Utilities.gzip(data);
		assertArrayEquals(data, Utilities.gunzip(compressedData));
		assertArrayEquals(new byte[0], Utilities.gunzip(Utilities.gzip(new byte[0])));
		assertTrue(assertThrows(Exception.class, () -> Utilities.gunzip(new byte[] { 1, 2, 3 })).getMessage().contains("GZIP decompression failed"));
	}

	// ---- XML ----

	@Test
	public void testXmlDocumentDetection() {
		assertTrue(Utilities.isXmlDocument("<?xml version=\"1.0\"?><a/>".getBytes(StandardCharsets.UTF_8)));
		assertTrue(Utilities.isXmlDocument("<?XML version=\"1.0\"?><a/>".getBytes(StandardCharsets.UTF_8)));
		assertFalse(Utilities.isXmlDocument("<a/>".getBytes(StandardCharsets.UTF_8)));
		assertFalse(Utilities.isXmlDocument("<?xml".getBytes(StandardCharsets.UTF_8)));
		assertFalse(Utilities.isXmlDocument(null));
	}

	@Test
	public void testParseXml() throws Exception {
		final Document document = Utilities.parseXmlFile("<?xml version=\"1.0\"?><Root><Child Attr=\"x\">value</Child><Empty/><Nested><Inner>text</Inner></Nested></Root>".getBytes(StandardCharsets.UTF_8));
		final Map<String, Node> childNodes = Utilities.getChildNodesMap(document.getDocumentElement());
		assertEquals("[Child, Empty, Nested]", childNodes.keySet().toString());
		assertEquals("value", Utilities.getNodeValue(childNodes.get("Child")));
		assertEquals("text", Utilities.getNodeValue(childNodes.get("Nested")));
		assertNull(Utilities.getNodeValue(childNodes.get("Empty")));
		assertEquals("x", Utilities.getAttributeValue(childNodes.get("Child"), "attr"));
		assertNull(Utilities.getAttributeValue(childNodes.get("Child"), "Other"));
		assertNull(Utilities.getAttributeValue(document, "Other"));

		assertTrue(assertThrows(Exception.class, () -> Utilities.parseXmlFile("<Root>".getBytes(StandardCharsets.UTF_8))).getMessage().startsWith("Cannot parse XML data"));
	}

	@Test
	public void testParseXmlRejectsDoctype() {
		// Protection against XML external entity (XXE) and entity expansion attacks
		final String xxe = "<?xml version=\"1.0\"?><!DOCTYPE Root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><Root>&xxe;</Root>";
		assertThrows(Exception.class, () -> Utilities.parseXmlFile(xxe.getBytes(StandardCharsets.UTF_8)));
		final String billionLaughs = "<?xml version=\"1.0\"?><!DOCTYPE Root [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]><Root>&b;</Root>";
		assertThrows(Exception.class, () -> Utilities.parseXmlFile(billionLaughs.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	public void testCreateXml() throws Exception {
		final Document document = Utilities.createNewDocument();
		final Element root = Utilities.appendNode(document, "Root");
		final Element child = Utilities.appendNode(root, "Child");
		Utilities.appendAttribute(child, "Set", "value");
		Utilities.appendAttribute(child, "Empty", null);
		Utilities.appendTextValueNode(root, "Text", "content");
		Utilities.appendTextValueNode(root, "NoText", null);

		assertEquals("value", child.getAttribute("Set"));
		assertTrue(child.hasAttribute("Empty"));
		assertEquals("", child.getAttribute("Empty"));
		assertEquals("content", Utilities.getNodeValue(Utilities.getChildNodesMap(root).get("Text")));
		assertFalse(Utilities.getChildNodesMap(root).get("NoText").hasChildNodes());
	}

	// ---- Version ----

	@Test
	public void testVersion() throws Exception {
		final Version version = new Version("4.10.2");
		assertEquals(4, version.getMajorVersionNumber());
		assertEquals(10, version.getMinorVersionNumber());
		assertEquals(2, version.getMicroVersionNumber());
		assertEquals("4.10.2", version.toString());
		assertEquals(new Version(4, 10, 2), version);
		assertEquals(new Version(4, 10, 2).hashCode(), version.hashCode());
		assertEquals(version, version);
		assertNotEquals(version, "4.10.2");
		assertNotEquals(version, new Version(4, 10, 3));
		assertNotEquals(version, new Version(4, 11, 2));
		assertNotEquals(version, new Version(5, 10, 2));

		for (final String invalidVersion : new String[] { null, "", "4.1", "4.1.0.1", "a.b.c", " 4.1.0" }) {
			assertThrows(Exception.class, () -> new Version(invalidVersion), invalidVersion);
		}
	}

	@Test
	public void testVersionComparison() {
		final Version version = new Version(2, 5, 7);
		assertEquals(0, version.compareTo(new Version(2, 5, 7)));
		assertEquals(1, version.compareTo(null));
		assertEquals(1, version.compareTo(new Version(1, 9, 9)));
		assertEquals(-1, version.compareTo(new Version(3, 0, 0)));
		assertEquals(1, version.compareTo(new Version(2, 4, 9)));
		assertEquals(-1, version.compareTo(new Version(2, 6, 0)));
		assertEquals(1, version.compareTo(new Version(2, 5, 6)));
		assertEquals(-1, version.compareTo(new Version(2, 5, 8)));
	}

	@Test
	public void testVersionFromText() {
		assertEquals(new Version(1, 2, 3), Version.getFirstFullVersionNumberFromText("Release 1.2.3 (build 4.5.6)"));
		assertNull(Version.getFirstFullVersionNumberFromText("Version 1.2"));
		assertNull(Version.getFirstFullVersionNumberFromText(" "));
		assertNull(Version.getFirstFullVersionNumberFromText(null));
		// A version part exceeding the int range is skipped
		assertEquals(new Version(2, 0, 1), Version.getFirstFullVersionNumberFromText("Build 1.0.20240101123456 then 2.0.1"));
		assertNull(Version.getFirstFullVersionNumberFromText("Build 1.0.20240101123456"));
	}

	// ---- VariantDictionary ----

	@Test
	public void testVariantDictionaryAllTypesRoundTrip() throws Exception {
		final VariantDictionary dictionary = new VariantDictionary();
		dictionary.put("uint32", VariantDictionaryEntry.Type.UINT_32, 0xFFFFFFFF);
		dictionary.put("uint64", VariantDictionaryEntry.Type.UINT_64, 0xFFFFFFFF_FFFFFFFFL);
		dictionary.put("int32", VariantDictionaryEntry.Type.INT_32, -5);
		dictionary.put("int64", VariantDictionaryEntry.Type.INT_64, -6L);
		dictionary.put("true", VariantDictionaryEntry.Type.BOOL, true);
		dictionary.put("false", VariantDictionaryEntry.Type.BOOL, false);
		dictionary.put("string", VariantDictionaryEntry.Type.STRING, "\u00c4bc");
		dictionary.put("bytes", VariantDictionaryEntry.Type.BYTE_ARRAY, new byte[] { 1, 2, 3 });

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		dictionary.write(outputStream);
		final VariantDictionary readDictionary = VariantDictionary.read(new ByteArrayInputStream(outputStream.toByteArray()));

		assertEquals(dictionary.keySet(), readDictionary.keySet());
		assertEquals(0xFFFFFFFF, readDictionary.get("uint32").getJavaValue());
		assertEquals(0xFFFFFFFF_FFFFFFFFL, readDictionary.get("uint64").getJavaValue());
		assertEquals(-5, readDictionary.get("int32").getJavaValue());
		assertEquals(-6L, readDictionary.get("int64").getJavaValue());
		assertEquals(Boolean.TRUE, readDictionary.get("true").getJavaValue());
		assertEquals(Boolean.FALSE, readDictionary.get("false").getJavaValue());
		assertEquals("\u00c4bc", readDictionary.get("string").getJavaValue());
		assertArrayEquals(new byte[] { 1, 2, 3 }, (byte[]) readDictionary.get("bytes").getJavaValue());
		assertEquals(VariantDictionaryEntry.Type.STRING, readDictionary.get("string").getType());
		assertArrayEquals("\u00c4bc".getBytes(StandardCharsets.UTF_8), readDictionary.get("string").getValue());
	}

	@Test
	public void testVariantDictionaryTypes() {
		for (final VariantDictionaryEntry.Type type : VariantDictionaryEntry.Type.values()) {
			assertEquals(type, VariantDictionaryEntry.Type.fromTypeId(type.getId()));
		}
		assertThrows(RuntimeException.class, () -> VariantDictionaryEntry.Type.fromTypeId(0x99));
		assertEquals(Void.class, VariantDictionaryEntry.Type.END.getJavaType());
		assertEquals(byte[].class, VariantDictionaryEntry.Type.BYTE_ARRAY.getJavaType());
		assertArrayEquals(new byte[0], VariantDictionaryEntry.Type.END.fromJavaValue(null));
		assertNull(VariantDictionaryEntry.Type.END.toJavaValue(new byte[0]));

		assertThrows(IllegalArgumentException.class, () -> VariantDictionaryEntry.Type.BOOL.toJavaValue(new byte[2]));
		assertThrows(IllegalArgumentException.class, () -> VariantDictionaryEntry.Type.BOOL.toJavaValue(new byte[] { 2 }));
		assertThrows(RuntimeException.class, () -> VariantDictionaryEntry.Type.INT_32.toJavaValue(new byte[8]));

		final VariantDictionaryEntry entry = new VariantDictionaryEntry(VariantDictionaryEntry.Type.INT_32, new byte[4]);
		entry.setJavaValue(7);
		assertArrayEquals(new byte[] { 7, 0, 0, 0 }, entry.getValue());
	}

	@Test
	public void testVariantDictionaryVersion() throws Exception {
		final VariantDictionary dictionary = new VariantDictionary();
		dictionary.put("k", VariantDictionaryEntry.Type.STRING, "v");
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		dictionary.write(outputStream);
		final byte[] data = outputStream.toByteArray();

		// A newer minor version (low byte) is accepted
		final byte[] newerMinorVersion = data.clone();
		newerMinorVersion[0] = (byte) 0xFF;
		assertEquals("v", VariantDictionary.read(new ByteArrayInputStream(newerMinorVersion)).get("k").getJavaValue());

		final byte[] otherMajorVersion = data.clone();
		otherMajorVersion[1] = 0x02;
		assertTrue(assertThrows(Exception.class, () -> VariantDictionary.read(new ByteArrayInputStream(otherMajorVersion))).getMessage().contains("Unsupported VariantDictionary version"));
		assertThrows(EOFException.class, () -> VariantDictionary.read(new ByteArrayInputStream(new byte[1])));
	}

	@Test
	public void testVariantDictionaryInvalidLengths() {
		final byte[] negativeKeyLength = Utilities.concatArrays(Utilities.concatArrays(VariantDictionary.VERSION, new byte[] { 0x18 }), Utilities.getLittleEndianBytes(-1));
		assertTrue(assertThrows(Exception.class, () -> VariantDictionary.read(new ByteArrayInputStream(negativeKeyLength))).getMessage().contains("Invalid negative VariantDictionary key length"));

		final byte[] excessiveKeyLength = Utilities.concatArrays(Utilities.concatArrays(VariantDictionary.VERSION, new byte[] { 0x18 }), Utilities.getLittleEndianBytes(Integer.MAX_VALUE));
		assertTrue(assertThrows(Exception.class, () -> VariantDictionary.read(new ByteArrayInputStream(excessiveKeyLength))).getMessage().contains("exceeds maximum allowed size"));

		final byte[] truncatedValue = Utilities.concatArrays(Utilities.concatArrays(Utilities.concatArrays(VariantDictionary.VERSION, new byte[] { 0x18 }), Utilities.getLittleEndianBytes(1)),
				Utilities.concatArrays(new byte[] { 'k' }, Utilities.getLittleEndianBytes(10)));
		assertThrows(EOFException.class, () -> VariantDictionary.read(new ByteArrayInputStream(truncatedValue)));

		final byte[] negativeValueLength = Utilities.concatArrays(Utilities.concatArrays(Utilities.concatArrays(VariantDictionary.VERSION, new byte[] { 0x18 }), Utilities.getLittleEndianBytes(1)),
				Utilities.concatArrays(new byte[] { 'k' }, Utilities.getLittleEndianBytes(-2)));
		assertTrue(assertThrows(Exception.class, () -> VariantDictionary.read(new ByteArrayInputStream(negativeValueLength))).getMessage().contains("Invalid negative VariantDictionary value length"));
	}

	@Test
	public void testVariantDictionaryWithoutEndMarker() {
		// The end of the stream (-1) is no valid type id
		assertThrows(RuntimeException.class, () -> VariantDictionary.read(new ByteArrayInputStream(VariantDictionary.VERSION)));
	}

	// ---- Type length value structures ----

	@Test
	public void testTypeLengthValueStructureRoundTrip() throws Exception {
		for (final boolean useIntLength : new boolean[] { true, false }) {
			// 40000 bytes need the full unsigned range of the 16 bit length
			for (final byte[] data : new byte[][] { new byte[0], new byte[] { 1, 2, 3 }, new byte[40000] }) {
				final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				new TypeLengthValueStructure(7, data).write(outputStream, useIntLength);
				final TypeLengthValueStructure structure = TypeLengthValueStructure.read(new ByteArrayInputStream(outputStream.toByteArray()), useIntLength);
				assertEquals(7, structure.getTypeId());
				assertArrayEquals(data, structure.getData());
			}

			final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			new TypeLengthValueStructure(8, null).write(outputStream, useIntLength);
			assertEquals(0, TypeLengthValueStructure.read(new ByteArrayInputStream(outputStream.toByteArray()), useIntLength).getData().length);
		}
	}

	@Test
	public void testTypeLengthValueStructureErrors() throws Exception {
		assertThrows(java.io.IOException.class, () -> new TypeLengthValueStructure(1, new byte[0x10000]).write(new ByteArrayOutputStream(), false));
		assertThrows(EOFException.class, () -> TypeLengthValueStructure.read(new ByteArrayInputStream(new byte[0]), true));
		assertThrows(EOFException.class, () -> TypeLengthValueStructure.read(new ByteArrayInputStream(new byte[] { 1, 5, 0, 0, 0, 1 }), true));

		final byte[] negativeLength = Utilities.concatArrays(new byte[] { 1 }, Utilities.getLittleEndianBytes(-1));
		assertTrue(assertThrows(Exception.class, () -> TypeLengthValueStructure.read(new ByteArrayInputStream(negativeLength), true)).getMessage().contains("Invalid negative"));
		final byte[] longData = Utilities.concatArrays(new byte[] { 1 }, Utilities.getLittleEndianBytes(11));
		assertTrue(assertThrows(Exception.class, () -> TypeLengthValueStructure.read(new ByteArrayInputStream(longData), true, 10)).getMessage().contains("exceeds maximum allowed size of 10"));
	}

	@Test
	public void testTypeHashLengthValueStructure() throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		TypeHashLengthValueStructure.write(outputStream, 3, new byte[] { 1, 2 }, "SHA-256");
		TypeHashLengthValueStructure.write(outputStream, 4, null, "SHA-256");
		final ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());

		final TypeHashLengthValueStructure structure = TypeHashLengthValueStructure.read(inputStream, "SHA-256");
		assertEquals(3, structure.getTypeId());
		assertArrayEquals(new byte[] { 1, 2 }, structure.getData());
		assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256").digest(new byte[] { 1, 2 }), structure.getHash());

		// The terminating block has no data and a zero hash
		final TypeHashLengthValueStructure endStructure = TypeHashLengthValueStructure.read(inputStream, "SHA-256");
		assertEquals(4, endStructure.getTypeId());
		assertEquals(0, endStructure.getData().length);
		assertArrayEquals(new byte[32], endStructure.getHash());
	}

	@Test
	public void testTypeHashLengthValueStructureErrors() throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		TypeHashLengthValueStructure.write(outputStream, 0, new byte[] { 1, 2 }, "SHA-256");
		final byte[] corruptedData = outputStream.toByteArray();
		corruptedData[corruptedData.length - 1] ^= 1;
		assertTrue(assertThrows(RuntimeException.class, () -> TypeHashLengthValueStructure.read(new ByteArrayInputStream(corruptedData), "SHA-256")).getMessage().contains("Checksum failure"));

		final byte[] negativeLength = Utilities.concatArrays(Utilities.concatArrays(new byte[4], new byte[32]), Utilities.getLittleEndianBytes(-1));
		assertTrue(assertThrows(Exception.class, () -> TypeHashLengthValueStructure.read(new ByteArrayInputStream(negativeLength), "SHA-256")).getMessage().contains("Invalid negative"));
		final byte[] excessiveLength = Utilities.concatArrays(Utilities.concatArrays(new byte[4], new byte[32]), Utilities.getLittleEndianBytes(Integer.MAX_VALUE));
		assertTrue(assertThrows(Exception.class, () -> TypeHashLengthValueStructure.read(new ByteArrayInputStream(excessiveLength), "SHA-256")).getMessage().contains("exceeds maximum allowed size"));
		assertThrows(EOFException.class, () -> TypeHashLengthValueStructure.read(new ByteArrayInputStream(new byte[10]), "SHA-256"));
	}
}
