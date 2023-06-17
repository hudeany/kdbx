package de.soderer.utilities.kdbx.util;

import java.io.InputStream;

public class TypeLengthValueStructure {
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

	public static TypeLengthValueStructure read(final InputStream inputStream, final boolean useIntLength) throws Exception {
		final int typeId = inputStream.read();
		int length;
		if (useIntLength) {
			length = Utilities.readLittleEndianIntFromStream(inputStream);
		} else {
			length = Utilities.readLittleEndianShortFromStream(inputStream);
		}
		final byte[] data;
		if (length > 0) {
			data = new byte[length];
			final int bytesRead = inputStream.read(data);
			if (bytesRead != length) {
				throw new Exception("Cannot read TypeLengthValueStructure data of length " + length);
			}
		} else {
			data = new byte[0];
		}
		return new TypeLengthValueStructure(typeId, data);
	}
}
