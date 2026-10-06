package de.soderer.utilities.kdbx.utilities;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Helper methods for strings, byte data, streams, XML and compression used by the KDBX library.
 */
public class Utilities {
	/**
	 * Pattern of hexadecimal text.
	 */
	private static final Pattern HEXADECIMAL_PATTERN = Pattern.compile("\\p{XDigit}*");

	/**
	 * Utility class, not to be instantiated.
	 */
	private Utilities() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * Checks for a null, empty or whitespace only string.
	 *
	 * @param value the string
	 * @return true for null, empty or whitespace only
	 */
	public static boolean isBlank(final String value) {
		return value == null || value.length() == 0 || value.trim().length() == 0;
	}

	/**
	 * Checks for a string with at least one non whitespace character.
	 *
	 * @param value the string
	 * @return true for a string with non whitespace content
	 */
	public static boolean isNotBlank(final String value) {
		return !isBlank(value);
	}

	/**
	 * Reads all remaining data of a stream.
	 *
	 * @param inputStream the stream
	 * @return the data or null for a null stream
	 * @throws IOException if reading fails
	 */
	public static byte[] toByteArray(final InputStream inputStream) throws IOException {
		if (inputStream == null) {
			return null;
		} else {
			try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
				copy(inputStream, byteArrayOutputStream);
				return byteArrayOutputStream.toByteArray();
			}
		}
	}

	/**
	 * Copies all remaining data of a stream into another stream.
	 *
	 * @param inputStream source stream
	 * @param outputStream destination stream
	 * @return number of copied bytes
	 * @throws IOException if reading or writing fails
	 */
	public static long copy(final InputStream inputStream, final OutputStream outputStream) throws IOException {
		final byte[] buffer = new byte[4096];
		int lengthRead = -1;
		long bytesCopied = 0;
		while ((lengthRead = inputStream.read(buffer)) > -1) {
			outputStream.write(buffer, 0, lengthRead);
			bytesCopied += lengthRead;
		}
		outputStream.flush();
		return bytesCopied;
	}

	/**
	 * Converts data to uppercase hexadecimal text with "_" between the bytes.
	 *
	 * @param data the data
	 * @return the hexadecimal text or "&lt;empty&gt;" for null or empty data
	 */
	public static String toHexString(final byte[] data) {
		return toHexString(data, "_");
	}

	/**
	 * Converts hexadecimal text (optionally with prefix "0x") to data.
	 *
	 * @param value the hexadecimal text
	 * @return the data or null for null text
	 * @throws RuntimeException if the text contains non hexadecimal characters or has an odd length
	 */
	public static byte[] fromHexString(final String value) {
		if (value == null) {
			return null;
		} else {
			String decodeValue = value;
			if (value.toLowerCase().startsWith("0x")) {
				decodeValue = decodeValue.substring(2);
			}
			if (!HEXADECIMAL_PATTERN.matcher(decodeValue).matches()) {
				throw new RuntimeException("String contains non hexadecimal character: " + value);
			} else if (decodeValue.length() % 2 != 0) {
				throw new RuntimeException("Hexadecimal string has odd number of characters: " + value);
			}
			final int length = decodeValue.length();
			final byte[] data = new byte[length / 2];
			for (int i = 0; i < length; i += 2) {
				data[i / 2] = (byte) ((Character.digit(decodeValue.charAt(i), 16) << 4) + Character.digit(decodeValue.charAt(i + 1), 16));
			}
			return data;
		}
	}

	/**
	 * Converts hexadecimal text to data, optionally ignoring all non hexadecimal characters (e.g. separators and whitespace).
	 *
	 * @param value the hexadecimal text
	 * @param ignoreNonHexCharacters true to remove all non hexadecimal characters before conversion
	 * @return the data or null for null text
	 * @throws RuntimeException if the text is no valid hexadecimal text
	 */
	public static byte[] fromHexString(final String value, final boolean ignoreNonHexCharacters) {
		if (value == null) {
			return null;
		} else if (ignoreNonHexCharacters) {
			return fromHexString(value.toLowerCase().replaceAll("[^abcdef0-9]", ""));
		} else {
			return fromHexString(value);
		}
	}

	/**
	 * Converts data to uppercase hexadecimal text.
	 *
	 * @param data the data
	 * @param separator separator between the bytes
	 * @return the hexadecimal text or "&lt;empty&gt;" for null or empty data
	 */
	public static String toHexString(final byte[] data, final String separator) {
		if (data == null || data.length == 0) {
			return "<empty>";
		}
		final StringBuilder buffer = new StringBuilder();
		final char[] chars = "0123456789ABCDEF".toCharArray();
		for (int i = 0; i < data.length; i++) {
			final int value = data[i] & 0xff;
			final char hi = chars[(value & 0xf0) >>> 4];
			final char lo = chars[value & 0x0f];
			buffer.append(hi).append(lo);
			if ((i + 1) < data.length) {
				buffer.append(separator);
			}
		}
		return buffer.toString();
	}

	/**
	 * Reads a little endian 32 bit integer from a stream. Partial reads of the stream are handled.
	 *
	 * @param inputStream the stream
	 * @return the value
	 * @throws IOException if reading fails
	 * @throws Exception if the stream ends before 4 bytes are read
	 */
	public static int readLittleEndianIntFromStream(final InputStream inputStream) throws IOException, Exception {
		// readNBytes loops until all bytes are read, because a single read() call may legally return less data (e.g. GZIPInputStream, CipherInputStream, network streams)
		final byte[] byteBuffer = inputStream.readNBytes(4);
		if (byteBuffer.length == 0) {
			throw new Exception("Cannot read int from stream: End of stream");
		} else if (byteBuffer.length != 4) {
			throw new Exception("Cannot read int from stream: Not enough data left");
		}
		return ByteBuffer.wrap(byteBuffer).order(ByteOrder.LITTLE_ENDIAN).getInt();
	}

	/**
	 * Reads a little endian 16 bit integer from a stream. Partial reads of the stream are handled.
	 *
	 * @param inputStream the stream
	 * @return the value
	 * @throws IOException if reading fails
	 * @throws Exception if the stream ends before 2 bytes are read
	 */
	public static short readLittleEndianShortFromStream(final InputStream inputStream) throws IOException, Exception {
		final byte[] byteBuffer = inputStream.readNBytes(2);
		if (byteBuffer.length == 0) {
			throw new Exception("Cannot read short from stream: End of stream");
		} else if (byteBuffer.length != 2) {
			throw new Exception("Cannot read short from stream: Not enough data left");
		}
		return ByteBuffer.wrap(byteBuffer).order(ByteOrder.LITTLE_ENDIAN).getShort();
	}

	/**
	 * Reads an exact number of bytes from a stream. Partial reads of the stream are handled.
	 *
	 * @param inputStream the stream
	 * @param length number of bytes to read
	 * @param description description of the data for the error message
	 * @return the data
	 * @throws IOException if reading fails or the stream ends prematurely
	 */
	public static byte[] readFully(final InputStream inputStream, final int length, final String description) throws IOException {
		final byte[] data = inputStream.readNBytes(length);
		if (data.length != length) {
			throw new EOFException("Cannot read " + description + ": premature end of stream after " + data.length + " of " + length + " bytes");
		}
		return data;
	}

	/**
	 * Reads a signed little endian integer of 1, 2, 4 or 8 bytes.
	 *
	 * @param data the data
	 * @return the value
	 * @throws RuntimeException for other data lengths
	 */
	public static long readLittleEndianValueFromByteArray(final byte[] data) {
		switch (data.length) {
			case 1:
				return data[0];
			case 2:
				return ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getShort();
			case 4:
				return ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt();
			case 8:
				return ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getLong();
			default:
				throw new RuntimeException("Invalid data length for numeric value");
		}
	}

	/**
	 * Encodes characters as UTF-8 without creating an intermediate String. The temporary encoding buffer is cleared.
	 *
	 * @param chars the characters
	 * @return the UTF-8 data
	 */
	public static byte[] toBytes(final char[] chars) {
		final CharBuffer charBuffer = CharBuffer.wrap(chars);
		final ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
		final byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
		return bytes;
	}

	/**
	 * AES-KDF: encrypts a key repeatedly with AES in ECB mode.
	 *
	 * @param salt AES key (transform seed)
	 * @param rounds number of encryption rounds
	 * @param originalKey the key to transform (multiple of 16 bytes)
	 * @return the transformed key
	 * @throws RuntimeException if encryption fails
	 */
	public final static byte[] deriveKeyByAES(final byte[] salt, final long rounds, final byte[] originalKey) {
		byte[] result = new byte[originalKey.length];
		System.arraycopy(originalKey, 0, result, 0, result.length);
		try {
			final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(salt, "AES"));
			for (long i = 0; i < rounds; i++) {
				result = cipher.doFinal(result);
			}
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
		return result;
	}

	/**
	 * Concatenates two byte arrays.
	 *
	 * @param array1 first array
	 * @param array2 second array
	 * @return new array with the content of both arrays
	 */
	public static byte[] concatArrays(final byte[] array1, final byte[] array2) {
		final byte[] result = new byte[array1.length + array2.length];
		int writeIndex = 0;
		for (final byte byte1 : array1) {
			result[writeIndex++] = byte1;
		}
		for (final byte byte2 : array2) {
			result[writeIndex++] = byte2;
		}
		return result;
	}

	/**
	 * Returns the little endian bytes of a 16 bit integer.
	 *
	 * @param value the value
	 * @return 2 bytes
	 */
	public static byte[] getLittleEndianBytes(final short value) {
		return ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(value).array();
	}

	/**
	 * Reads a little endian 32 bit integer.
	 *
	 * @param dataBytes exactly 4 bytes
	 * @return the value
	 * @throws RuntimeException for invalid data
	 */
	public static int readIntFromLittleEndianBytes(final byte[] dataBytes) {
		if (dataBytes == null || dataBytes.length != 4) {
			throw new RuntimeException("Invalid data bytes for int value: 4 bytes expected");
		} else {
			return ByteBuffer.wrap(dataBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
		}
	}

	/**
	 * Returns the little endian bytes of a 32 bit integer.
	 *
	 * @param value the value
	 * @return 4 bytes
	 */
	public static byte[] getLittleEndianBytes(final int value) {
		return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
	}

	/**
	 * Reads a little endian 64 bit integer.
	 *
	 * @param dataBytes exactly 8 bytes
	 * @return the value
	 * @throws RuntimeException for invalid data
	 */
	public static long readLongFromLittleEndianBytes(final byte[] dataBytes) {
		if (dataBytes == null || dataBytes.length != 8) {
			throw new RuntimeException("Invalid data bytes for long value: 8 bytes expected");
		} else {
			return ByteBuffer.wrap(dataBytes).order(ByteOrder.LITTLE_ENDIAN).getLong();
		}
	}

	/**
	 * Returns the little endian bytes of a 64 bit integer.
	 *
	 * @param value the value
	 * @return 8 bytes
	 */
	public static byte[] getLittleEndianBytes(final long value) {
		return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array();
	}

	/**
	 * Checks whether data starts with an XML declaration ("&lt;?xml ").
	 *
	 * @param data the data
	 * @return true for data starting with an XML declaration
	 */
	public static boolean isXmlDocument(final byte[] data) {
		if (data == null || data.length < 6) {
			return false;
		} else {
			return "<?xml ".equals(new String(Arrays.copyOfRange(data, 0, 6), StandardCharsets.UTF_8).toLowerCase());
		}
	}

	/**
	 * Parses XML data with a parser hardened against XXE attacks (no DOCTYPE, no external entities).
	 *
	 * @param xmlData the XML data
	 * @return the document
	 * @throws Exception if the data is no well-formed XML
	 */
	public static Document parseXmlFile(final byte[] xmlData) throws Exception {
		try (BufferedInputStream inputStream = new BufferedInputStream(new ByteArrayInputStream(xmlData))) {
			final DocumentBuilderFactory documentBuilderFactory = createHardenedDocumentBuilderFactory();
			final DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
			// Suppress the default error output of the parser on System.err, fatal errors are reported via the thrown exception
			documentBuilder.setErrorHandler(new DefaultHandler());
			return documentBuilder.parse(inputStream);
		} catch (final Exception e) {
			throw new Exception("Cannot parse XML data: " + e.getMessage(), e);
		}
	}

	/**
	 * Creates a DocumentBuilderFactory, which rejects DOCTYPE declarations and does not resolve external entities.
	 *
	 * @return the factory
	 * @throws ParserConfigurationException if a feature is not supported
	 */
	private static DocumentBuilderFactory createHardenedDocumentBuilderFactory() throws ParserConfigurationException {
		final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
		documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
		documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
		documentBuilderFactory.setXIncludeAware(false);
		documentBuilderFactory.setExpandEntityReferences(false);
		return documentBuilderFactory;
	}

	/**
	 * Returns the value of a node or the value of its first descendant with a value.
	 *
	 * @param pNode the node
	 * @return the value or null
	 */
	public static String getNodeValue(final Node pNode) {
		if (pNode.getNodeValue() != null) {
			return pNode.getNodeValue();
		} else if (pNode.getFirstChild() != null) {
			return getNodeValue(pNode.getFirstChild());
		} else {
			return null;
		}
	}

	/**
	 * Returns the value of an attribute, searched by name case insensitive.
	 *
	 * @param pNode the node
	 * @param pAttributeName name of the attribute
	 * @return the value or null if the attribute does not exist
	 */
	public static String getAttributeValue(final Node pNode, final String pAttributeName) {
		String returnString = null;

		final NamedNodeMap attributes = pNode.getAttributes();
		if (attributes != null) {
			for (int i = 0; i < attributes.getLength(); i++) {
				if (attributes.item(i).getNodeName().equalsIgnoreCase(pAttributeName)) {
					returnString = attributes.item(i).getNodeValue();
					break;
				}
			}
		}

		return returnString;
	}

	/**
	 * Returns the child nodes (except text nodes) by their names. For several child nodes with the same name only the last one is returned.
	 *
	 * @param dataNode the parent node
	 * @return the child nodes by name
	 */
	public static Map<String, Node> getChildNodesMap(final Node dataNode) {
		final Map<String, Node> childNodes = new LinkedHashMap<>();
		final NodeList childNodesList = dataNode.getChildNodes();
		for (int i = 0; i < childNodesList.getLength(); i++) {
			final Node childNode = childNodesList.item(i);
			if (childNode.getNodeType() != Node.TEXT_NODE) {
				childNodes.put(childNode.getNodeName(), childNode);
			}
		}

		return childNodes;
	}

	/**
	 * Creates an empty XML document.
	 *
	 * @return the document
	 * @throws ParserConfigurationException if no parser is available
	 */
	public static Document createNewDocument() throws ParserConfigurationException {
		final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		final DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		final Document document = documentBuilder.newDocument();
		return document;
	}

	/**
	 * Appends the root element to a document.
	 *
	 * @param document the document
	 * @param tagName name of the element
	 * @return the new element
	 */
	public static Element appendNode(final Document document, final String tagName) {
		final Element newNode = document.createElement(tagName);
		document.appendChild(newNode);
		return newNode;
	}

	/**
	 * Appends a child element.
	 *
	 * @param baseNode the parent node
	 * @param tagName name of the element
	 * @return the new element
	 */
	public static Element appendNode(final Node baseNode, final String tagName) {
		final Element newNode = baseNode.getOwnerDocument().createElement(tagName);
		baseNode.appendChild(newNode);
		return newNode;
	}

	/**
	 * Appends a child element with text content.
	 *
	 * @param baseNode the parent node
	 * @param tagName name of the element
	 * @param tagValue text content or null for an empty element
	 * @return the new element
	 */
	public static Node appendTextValueNode(final Node baseNode, final String tagName, final String tagValue) {
		final Node newNode = appendNode(baseNode, tagName);
		if (tagValue != null) {
			newNode.appendChild(baseNode.getOwnerDocument().createTextNode(tagValue));
		}
		return newNode;
	}

	/**
	 * Sets an attribute of an element.
	 *
	 * @param baseNode the element
	 * @param attributeName name of the attribute
	 * @param attributeValue value of the attribute or null for an empty value
	 */
	public static void appendAttribute(final Element baseNode, final String attributeName, final String attributeValue) {
		final Attr typeAttribute = baseNode.getOwnerDocument().createAttribute(attributeName);
		if (attributeValue != null) {
			typeAttribute.setNodeValue(attributeValue);
		}
		baseNode.setAttributeNode(typeAttribute);
	}

	/**
	 * Compresses data with GZIP.
	 *
	 * @param data the data
	 * @return the compressed data
	 * @throws Exception if compression fails
	 */
	public static byte[] gzip(final byte[] data) throws Exception {
		final ByteArrayOutputStream bufferStream = new ByteArrayOutputStream();
		try (final GZIPOutputStream gzipOut = new GZIPOutputStream(bufferStream)) {
			gzipOut.write(data);
		} catch (final IOException e) {
			throw new Exception("GZIP compression failed", e);
		}
		return bufferStream.toByteArray();
	}

	/**
	 * Decompresses GZIP data.
	 *
	 * @param compressedData the compressed data
	 * @return the uncompressed data
	 * @throws Exception if the data is no valid GZIP data
	 */
	public static byte[] gunzip(final byte[] compressedData) throws Exception {
		try (final GZIPInputStream gzipIn = new GZIPInputStream(new ByteArrayInputStream(compressedData))) {
			return Utilities.toByteArray(gzipIn);
		} catch (final IOException e) {
			throw new Exception("GZIP decompression failed", e);
		}
	}
}
