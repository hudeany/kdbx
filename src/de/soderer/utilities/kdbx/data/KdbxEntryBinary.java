package de.soderer.utilities.kdbx.data;

public class KdbxEntryBinary {
	public int refID;
	public byte[] data;

	/**
	 * Unique id of this binary
	 */
	public KdbxEntryBinary setRefId(final int id) {
		refID = id;
		return this;
	}

	/**
	 * Unique id of this binary
	 */
	public int getRefId() {
		return refID;
	}

	/**
	 * Data of this binary.
	 */
	public KdbxEntryBinary setData(final byte[] data) {
		this.data = data;
		return this;
	}

	/**
	 * Data of this binary.
	 */
	public byte[] getData() {
		return data;
	}
}
