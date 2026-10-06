package de.soderer.utilities.kdbx.utilities;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;

/**
 * Payload block of the KDBX 3.x HashedBlockStream: block index (4 bytes), SHA-256 hash of the data (32 bytes), data length (4 bytes) and data.
 * A block with data length 0 and a zero hash terminates the payload.
 * <p>
 * For historical reasons the block index is called "type id" in this class.
 */
public class TypeHashLengthValueStructure {
	/**
	 * Sanity upper bound for a single payload block, to protect against maliciously crafted
	 * length values that could otherwise force huge memory allocations (Denial of Service protection).
	 */
	private static final int MAX_DATA_LENGTH = 64 * 1024 * 1024; // 64 MB

	/**
	 * Block index.
	 */
	int typeId;
	/**
	 * Hash of the data.
	 */
	byte[] hash;
	/**
	 * Data of the block.
	 */
	byte[] data;

	/**
	 * Returns the block index.
	 *
	 * @return the block index
	 */
	public int getTypeId() {
		return typeId;
	}

	/**
	 * Returns the hash of the data.
	 *
	 * @return the hash
	 */
	public byte[] getHash() {
		return hash;
	}

	/**
	 * Returns the data of the block.
	 *
	 * @return the data, empty for the terminating block
	 */
	public byte[] getData() {
		return data;
	}

	/**
	 * Creates a block.
	 *
	 * @param typeId block index
	 * @param hash hash of the data
	 * @param data data of the block
	 */
	public TypeHashLengthValueStructure(final int typeId, final byte[] hash, final byte[] data) {
		this.typeId = typeId;
		this.hash = hash;
		this.data = data;
	}

	/**
	 * Writes a block. For null data an empty block with zero hash is written (terminating block).
	 *
	 * @param outputStream the stream
	 * @param typeId block index
	 * @param data data of the block or null
	 * @param digestName name of the digest algorithm (e.g. "SHA-256")
	 * @throws Exception if writing fails
	 */
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

	/**
	 * Reads a block and verifies the hash of its data.
	 *
	 * @param inputStream the stream
	 * @param digestName name of the digest algorithm (e.g. "SHA-256")
	 * @return the block
	 * @throws Exception if the data is invalid, corrupted or the stream ends prematurely
	 */
	public static TypeHashLengthValueStructure read(final InputStream inputStream, final String digestName) throws Exception {
		final MessageDigest digest = MessageDigest.getInstance(digestName);

		final int typeId = Utilities.readLittleEndianIntFromStream(inputStream);

		final byte[] expectedHash = Utilities.readFully(inputStream, digest.getDigestLength(), "hash value");

		final int dataLength = Utilities.readLittleEndianIntFromStream(inputStream);
		if (dataLength < 0) {
			throw new Exception("Invalid negative TypeHashLengthValueStructure data length: " + dataLength);
		} else if (dataLength > MAX_DATA_LENGTH) {
			throw new Exception("TypeHashLengthValueStructure data length " + dataLength + " exceeds maximum allowed size of " + MAX_DATA_LENGTH + " bytes");
		}
		final byte[] data;
		if (dataLength > 0) {
			data = Utilities.readFully(inputStream, dataLength, "payload block data of expected length " + dataLength);
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

}
