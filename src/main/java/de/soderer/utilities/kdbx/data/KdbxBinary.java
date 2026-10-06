package de.soderer.utilities.kdbx.data;

/**
 * Binary attachment data as stored in the database file (KDBX 3.x meta data binaries or KDBX 4.x inner header), referenced by entry attachments via its id.
 */
public class KdbxBinary {
	/**
	 * Id, by which entry attachments reference this binary.
	 */
	private int id;
	/**
	 * Whether the data is GZIP compressed.
	 */
	private boolean compressed;
	/**
	 * Data, GZIP compressed if {@link #isCompressed()} is set.
	 */
	private byte[] data;

	/**
	 * Creates an empty binary.
	 */
	public KdbxBinary() {
		// nothing to do
	}

	/**
	 * Sets the id, by which entry attachments reference this binary.
	 *
	 * @param id the id, by which entry attachments reference this binary
	 */
	public void setId(final int id) {
		this.id = id;
	}

	/**
	 * Sets the id, by which entry attachments reference this binary and returns this object for method chaining.
	 *
	 * @param newId the id, by which entry attachments reference this binary
	 * @return this object
	 */
	public KdbxBinary withId(final int newId) {
		setId(newId);
		return this;
	}

	/**
	 * Returns the id, by which entry attachments reference this binary.
	 *
	 * @return the id, by which entry attachments reference this binary
	 */
	public int getId() {
		return id;
	}

	/**
	 * Sets whether the data is GZIP compressed.
	 *
	 * @param compressed whether the data is GZIP compressed
	 */
	public void setCompressed(final boolean compressed) {
		this.compressed = compressed;
	}

	/**
	 * Sets whether the data is GZIP compressed and returns this object for method chaining.
	 *
	 * @param newCompressed whether the data is GZIP compressed
	 * @return this object
	 */
	public KdbxBinary withCompressed(final boolean newCompressed) {
		setCompressed(newCompressed);
		return this;
	}

	/**
	 * Returns whether the data is GZIP compressed.
	 *
	 * @return whether the data is GZIP compressed
	 */
	public boolean isCompressed() {
		return compressed;
	}

	/**
	 * Sets the data, GZIP compressed if {@link #isCompressed()} is set.
	 *
	 * @param data the data, GZIP compressed if {@link #isCompressed()} is set
	 */
	public void setData(final byte[] data) {
		this.data = data;
	}

	/**
	 * Sets the data, GZIP compressed if {@link #isCompressed()} is set and returns this object for method chaining.
	 *
	 * @param newData the data, GZIP compressed if {@link #isCompressed()} is set
	 * @return this object
	 */
	public KdbxBinary withData(final byte[] newData) {
		setData(newData);
		return this;
	}

	/**
	 * Returns the data, GZIP compressed if {@link #isCompressed()} is set.
	 *
	 * @return the data, GZIP compressed if {@link #isCompressed()} is set
	 */
	public byte[] getData() {
		return data;
	}
}
