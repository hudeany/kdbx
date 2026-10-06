package de.soderer.utilities.kdbx.data;

import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * Attachment of an entry: a key (mostly a file name) and the attachment data, which is kept GZIP compressed in memory.
 */
public class KdbxEntryBinary {
	/**
	 * Key of this attachment, mostly a file name.
	 */
	private String key;
	/**
	 * Id of the referenced binary of the database file. It is set by the reader and by {@link de.soderer.utilities.kdbx.KdbxDatabase#validate()}.
	 */
	private Integer refID = null;
	/**
	 * GZIP compressed attachment data.
	 */
	private byte[] compressedData;

	/**
	 * Creates an empty entry attachment.
	 */
	public KdbxEntryBinary() {
		// nothing to do
	}

	/**
	 * Returns the key of this attachment, mostly a file name.
	 *
	 * @return the key of this attachment, mostly a file name
	 */
	public String getKey() {
		return key;
	}

	/**
	 * Sets the key of this attachment, mostly a file name.
	 *
	 * @param key the key of this attachment, mostly a file name
	 */
	public void setKey(final String key) {
		this.key = key;
	}

	/**
	 * Sets the key of this attachment, mostly a file name and returns this object for method chaining.
	 *
	 * @param newKey the key of this attachment, mostly a file name
	 * @return this object
	 */
	public KdbxEntryBinary withKey(final String newKey) {
		setKey(newKey);
		return this;
	}

	/**
	 * Returns the id of the binary of the database file, which contains the data of this attachment. It is set by the reader and by {@link de.soderer.utilities.kdbx.KdbxDatabase#validate()}, the data of this attachment is kept.
	 *
	 * @return the id of the binary of the database file, which contains the data of this attachment. It is set by the reader and by {@link de.soderer.utilities.kdbx.KdbxDatabase#validate()}, the data of this attachment is kept
	 */
	public Integer getRefId() {
		return refID;
	}

	/**
	 * Sets the id of the binary of the database file, which contains the data of this attachment. It is set by the reader and by {@link de.soderer.utilities.kdbx.KdbxDatabase#validate()}, the data of this attachment is kept.
	 *
	 * @param id the id of the binary of the database file, which contains the data of this attachment. It is set by the reader and by {@link de.soderer.utilities.kdbx.KdbxDatabase#validate()}, the data of this attachment is kept
	 */
	public void setRefId(final Integer id) {
		refID = id;
	}

	/**
	 * Sets the id of the binary of the database file, which contains the data of this attachment. It is set by the reader and by {@link de.soderer.utilities.kdbx.KdbxDatabase#validate()}, the data of this attachment is kept and returns this object for method chaining.
	 *
	 * @param newId the id of the binary of the database file, which contains the data of this attachment. It is set by the reader and by {@link de.soderer.utilities.kdbx.KdbxDatabase#validate()}, the data of this attachment is kept
	 * @return this object
	 */
	public KdbxEntryBinary withRefId(final Integer newId) {
		setRefId(newId);
		return this;
	}

	/**
	 * Returns the uncompressed data of this attachment.
	 * A new array is returned for each call.
	 *
	 * @return the uncompressed data or null if no data is set
	 * @throws Exception if decompression fails
	 */
	public byte[] getData() throws Exception {
		if (compressedData == null) {
			return null;
		} else {
			return Utilities.gunzip(compressedData);
		}
	}

	/**
	 * Sets the data of this attachment in GZIP compressed form.
	 *
	 * @param compressedData the GZIP compressed data
	 */
	public void setCompressedData(final byte[] compressedData) {
		this.compressedData = compressedData;
	}

	/**
	 * Sets the data of this attachment in GZIP compressed form and returns this object for method chaining.
	 *
	 * @param newCompressedData the GZIP compressed data
	 * @return this object
	 */
	public KdbxEntryBinary withCompressedData(final byte[] newCompressedData) {
		setCompressedData(newCompressedData);
		return this;
	}

	/**
	 * Sets the uncompressed data of this attachment, which is kept GZIP compressed in memory.
	 *
	 * @param data the uncompressed data or null
	 * @throws Exception if compression fails
	 */
	public void setData(final byte[] data) throws Exception {
		compressedData = data == null ? null : Utilities.gzip(data);
	}

	/**
	 * Sets the uncompressed data of this attachment and returns this object for method chaining.
	 *
	 * @param newData the uncompressed data or null
	 * @return this object
	 * @throws Exception if compression fails
	 */
	public KdbxEntryBinary withData(final byte[] newData) throws Exception {
		setData(newData);
		return this;
	}
}
