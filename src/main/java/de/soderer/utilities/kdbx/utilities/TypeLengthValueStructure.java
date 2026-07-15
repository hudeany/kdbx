package de.soderer.utilities.kdbx.utilities;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TypeLengthValueStructure {
	/**
	 * Sanity upper bound for a single TLV data field, to protect against maliciously crafted
	 * length values that could otherwise force huge memory allocations before any authentication
	 * of the file has taken place (Denial of Service protection).
	 */
	private static final int MAX_DATA_LENGTH = 16 * 1024 * 1024; // 16 MB

	int typeId;
	byte[] data;

	public int getTypeId() {
		return typeId;
	}

	public byte[] getData() {
		return data;
	}

	public TypeLengthValueStructure(final int typeId, final byte[] data) {
		this.typeId = typeId;
		this.data = data;
	}

	public void write(final OutputStream outputStream, final boolean useIntLength) throws IOException {
		outputStream.write(typeId);
		if (useIntLength) {
			outputStream.write(Utilities.getLittleEndianBytes(data == null ? 0 : data.length));
		} else {
			outputStream.write(Utilities.getLittleEndianBytes((short) (data == null ? 0 : data.length)));
		}
		if (data != null) {
			outputStream.write(data);
		}
	}

	public static TypeLengthValueStructure read(final InputStream inputStream, final boolean useIntLength) throws Exception {
		final int typeId = inputStream.read();

		int length;
		if (useIntLength) {
			length = Utilities.readLittleEndianIntFromStream(inputStream);
		} else {
			length = Utilities.readLittleEndianShortFromStream(inputStream);
		}
		if (length < 0) {
			throw new Exception("Invalid negative TypeLengthValueStructure data length: " + length);
		} else if (length > MAX_DATA_LENGTH) {
			throw new Exception("TypeLengthValueStructure data length " + length + " exceeds maximum allowed size of " + MAX_DATA_LENGTH + " bytes");
		}
		final byte[] data;
		if (length > 0) {
			data = new byte[length];
			readFully(inputStream, data);
		} else {
			data = new byte[0];
		}

		return new TypeLengthValueStructure(typeId, data);
	}

	/**
	 * Read exactly data.length bytes, looping over the underlying stream as needed, since a single
	 * InputStream#read(byte[]) call is not guaranteed to fill the buffer even before EOF is reached.
	 */
	private static void readFully(final InputStream inputStream, final byte[] data) throws IOException {
		int totalBytesRead = 0;
		while (totalBytesRead < data.length) {
			final int bytesRead = inputStream.read(data, totalBytesRead, data.length - totalBytesRead);
			if (bytesRead < 0) {
				throw new EOFException("Cannot read TypeLengthValueStructure data of length " + data.length + ": premature end of stream after " + totalBytesRead + " bytes");
			}
			totalBytesRead += bytesRead;
		}
	}
}
