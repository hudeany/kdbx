package de.soderer.utilities.kdbx.data;

public class KdbxEntryBinary {
	public int refID;
	public byte[] data;

	/**
	 * Unique id of this binary
	 * Dataversion <= 3.1 --> KdbxMeta binaries
	 * Dataversion >= 4.0 --> KdbxInnerHeaderType.BINARY_ATTACHMENT
	 */
	public KdbxEntryBinary setRefId(final int id) {
		refID = id;
		return this;
	}

	/**
	 * Unique id of this binary
	 * Dataversion <= 3.1 --> KdbxMeta binaries
	 * Dataversion >= 4.0 --> KdbxInnerHeaderType.BINARY_ATTACHMENT
	 */
	public int getRefId() {
		return refID;
	}

	/**
	 * Data of this binary.
	 * The same data should not be stored multiple times.
	 */
	public KdbxEntryBinary setData(final byte[] data) {
		this.data = data;
		return this;
	}

	/**
	 * Data of this binary.
	 * The same data should not be stored multiple times.
	 */
	public byte[] getData() {
		return data;
	}
}
