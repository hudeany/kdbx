package de.soderer.utilities.kdbx.util;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;

public class TypeHashLengthValueStructure {
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

	public static TypeHashLengthValueStructure read(final InputStream inputStream, final String digestName) throws Exception {
		final MessageDigest digest = MessageDigest.getInstance(digestName);

		final int typeId = Utilities.readLittleEndianIntFromStream(inputStream);

		final byte[] expectedHash = new byte[digest.getDigestLength()];
		final int readBytes = inputStream.read(expectedHash);
		if (readBytes != expectedHash.length) {
			throw new Exception("Cannot read hash value: premature end of data");
		}

		final int dataLength = Utilities.readLittleEndianIntFromStream(inputStream);
		final byte[] data;
		if (dataLength > 0) {
			data = new byte[dataLength];
			final int bytesRead = inputStream.read(data);
			if (bytesRead != dataLength) {
				throw new Exception("Cannot read TypeLengthValueStructure data of expected length: " + dataLength);
			}
		} else {
			data = new byte[0];
		}

		final byte[] generatedHash = digest.digest(data);
		if (dataLength > 0 && !Arrays.equals(expectedHash, generatedHash)) {
			throw new RuntimeException("Checksum failure");
		} else {
			return new TypeHashLengthValueStructure(typeId, expectedHash, data);
		}
	}
}
