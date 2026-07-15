package de.soderer.utilities.kdbx.utilities;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;

public class TypeHashLengthValueStructure {
	/**
	 * Sanity upper bound for a single payload block, to protect against maliciously crafted
	 * length values that could otherwise force huge memory allocations (Denial of Service protection).
	 */
	private static final int MAX_DATA_LENGTH = 64 * 1024 * 1024; // 64 MB

	int typeId;
	byte[] hash;
	byte[] data;

	public int getTypeId() {
		return typeId;
	}

	public byte[] getHash() {
		return hash;
	}

	public byte[] getData() {
		return data;
	}

	public TypeHashLengthValueStructure(final int typeId, final byte[] hash, final byte[] data) {
		this.typeId = typeId;
		this.hash = hash;
		this.data = data;
	}

	public static void write(final OutputStream outputStream, final int typeId, final byte[] data, final String digestName) throws Exception {
		final MessageDigest digest = MessageDigest.getInstance(digestName);

		outputStream.write(Utilities.getLittleEndianBytes(typeId));
		if (data != null) {
			outputStream.write(digest.digest(data));
			outputStream.write(Utilities.getLittleEndianBytes(data.length));
			outputStream.write(data);
		} else {
			outputStream.write(new byte[digest.getDigestLength()]);
			outputStream.write(Utilities.getLittleEndianBytes(0));
		}
	}

	public static TypeHashLengthValueStructure read(final InputStream inputStream, final String digestName) throws Exception {
		final MessageDigest digest = MessageDigest.getInstance(digestName);

		final int typeId = Utilities.readLittleEndianIntFromStream(inputStream);

		final byte[] expectedHash = new byte[digest.getDigestLength()];
		readFully(inputStream, expectedHash, "hash value");

		final int dataLength = Utilities.readLittleEndianIntFromStream(inputStream);
		if (dataLength < 0) {
			throw new Exception("Invalid negative TypeHashLengthValueStructure data length: " + dataLength);
		} else if (dataLength > MAX_DATA_LENGTH) {
			throw new Exception("TypeHashLengthValueStructure data length " + dataLength + " exceeds maximum allowed size of " + MAX_DATA_LENGTH + " bytes");
		}
		final byte[] data;
		if (dataLength > 0) {
			data = new byte[dataLength];
			readFully(inputStream, data, "TypeLengthValueStructure data of expected length: " + dataLength);
		} else {
			data = new byte[0];
		}

		final byte[] generatedHash = digest.digest(data);
		if (dataLength > 0 && !MessageDigest.isEqual(expectedHash, generatedHash)) {
			throw new RuntimeException("Checksum failure");
		} else {
			return new TypeHashLengthValueStructure(typeId, expectedHash, data);
		}
	}

	/**
	 * Read exactly data.length bytes, looping over the underlying stream as needed, since a single
	 * InputStream#read(byte[]) call is not guaranteed to fill the buffer even before EOF is reached.
	 */
	private static void readFully(final InputStream inputStream, final byte[] data, final String description) throws IOException {
		int totalBytesRead = 0;
		while (totalBytesRead < data.length) {
			final int bytesRead = inputStream.read(data, totalBytesRead, data.length - totalBytesRead);
			if (bytesRead < 0) {
				throw new EOFException("Cannot read " + description + ": premature end of stream after " + totalBytesRead + " bytes");
			}
			totalBytesRead += bytesRead;
		}
	}
}
