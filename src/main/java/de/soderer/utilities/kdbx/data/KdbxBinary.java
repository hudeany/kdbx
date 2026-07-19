package de.soderer.utilities.kdbx.data;

public class KdbxBinary {
	private int id;
	private boolean compressed;
	private byte[] data;

	/**
	 * Unique id of this binary
	 */
	public void setId(final int id) {
		this.id = id;
	}

	public KdbxBinary withId(final int newId) {
		setId(newId);
		return this;
	}

	/**
	 * Unique id of this binary
	 */
	public int getId() {
		return id;
	}

	/**
	 * Compression flag (GZIP)
	 */
	public void setCompressed(final boolean compressed) {
		this.compressed = compressed;
	}

	public KdbxBinary withCompressed(final boolean newCompressed) {
		setCompressed(newCompressed);
		return this;
	}

	/**
	 * Compression flag (GZIP)
	 */
	public boolean isCompressed() {
		return compressed;
	}

	/**
	 * Data of this binary.
	 * The same data should not be stored multiple times.
	 */
	public void setData(final byte[] data) {
		this.data = data;
	}

	public KdbxBinary withData(final byte[] newData) {
		setData(newData);
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
