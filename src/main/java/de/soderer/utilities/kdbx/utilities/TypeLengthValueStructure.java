package de.soderer.utilities.kdbx.utilities;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Header field of a KDBX file: type id (1 byte), data length (2 bytes in KDBX 3.x, 4 bytes in KDBX 4.x) and data.
 */
public class TypeLengthValueStructure {
	/**
	 * Sanity upper bound for a single TLV data field, to protect against maliciously crafted
	 * length values that could otherwise force huge memory allocations before any authentication
	 * of the file has taken place (Denial of Service protection).
	 */
	private static final int MAX_DATA_LENGTH = 16 * 1024 * 1024; // 16 MB

	/**
	 * Type id of the field.
	 */
	int typeId;
	/**
	 * Data of the field.
	 */
	byte[] data;

	/**
	 * Returns the type id of the field.
	 *
	 * @return the type id
	 */
	public int getTypeId() {
		return typeId;
	}

	/**
	 * Returns the data of the field.
	 *
	 * @return the data
	 */
	public byte[] getData() {
		return data;
	}

	/**
	 * Creates a field.
	 *
	 * @param typeId type id of the field
	 * @param data data of the field or null for no data
	 */
	public TypeLengthValueStructure(final int typeId, final byte[] data) {
		this.typeId = typeId;
		this.data = data;
	}

	/**
	 * Writes the field.
	 *
	 * @param outputStream the stream
	 * @param useIntLength true for a 4 bytes length (KDBX 4.x), false for 2 bytes (KDBX 3.x)
	 * @throws IOException if writing fails or the data is too long for a 2 bytes length
	 */
	public void write(final OutputStream outputStream, final boolean useIntLength) throws IOException {
		outputStream.write(typeId);
		if (useIntLength) {
			outputStream.write(Utilities.getLittleEndianBytes(data == null ? 0 : data.length));
		} else {
			if (data != null && data.length > 0xFFFF) {
				throw new IOException("TypeLengthValueStructure data length " + data.length + " exceeds the maximum of " + 0xFFFF + " bytes for 16 bit length fields");
			}
			outputStream.write(Utilities.getLittleEndianBytes((short) (data == null ? 0 : data.length)));
		}
		if (data != null) {
			outputStream.write(data);
		}
	}

	/**
	 * Reads a field with the default maximum data length of 16 MB, which protects against crafted length values in the unauthenticated outer header.
	 *
	 * @param inputStream the stream
	 * @param useIntLength true for a 4 bytes length (KDBX 4.x), false for 2 bytes (KDBX 3.x)
	 * @return the field
	 * @throws Exception if the data is invalid or the stream ends prematurely
	 */
	public static TypeLengthValueStructure read(final InputStream inputStream, final boolean useIntLength) throws Exception {
		return read(inputStream, useIntLength, MAX_DATA_LENGTH);
	}

	/**
	 * Reads a field.
	 *
	 * @param inputStream the stream
	 * @param useIntLength true for a 4 bytes length (KDBX 4.x), false for 2 bytes (KDBX 3.x)
	 * @param maxDataLength maximum accepted data length
	 * @return the field
	 * @throws Exception if the data is invalid or the stream ends prematurely
	 */
	public static TypeLengthValueStructure read(final InputStream inputStream, final boolean useIntLength, final int maxDataLength) throws Exception {
		final int typeId = inputStream.read();
		if (typeId < 0) {
			throw new EOFException("Cannot read TypeLengthValueStructure type id: premature end of stream");
		}

		int length;
		if (useIntLength) {
			length = Utilities.readLittleEndianIntFromStream(inputStream);
		} else {
			// KDBX 3 header field length is an unsigned 16 bit value
			length = Utilities.readLittleEndianShortFromStream(inputStream) & 0xFFFF;
		}
		if (length < 0) {
			throw new Exception("Invalid negative TypeLengthValueStructure data length: " + length);
		} else if (length > maxDataLength) {
			throw new Exception("TypeLengthValueStructure data length " + length + " exceeds maximum allowed size of " + maxDataLength + " bytes");
		}
		// readNBytes allocates memory step by step, so a wrong length value does not allocate the full size in advance
		final byte[] data = inputStream.readNBytes(length);
		if (data.length != length) {
			throw new EOFException("Cannot read TypeLengthValueStructure data of length " + length + ": premature end of stream after " + data.length + " bytes");
		}

		return new TypeLengthValueStructure(typeId, data);
	}
}
