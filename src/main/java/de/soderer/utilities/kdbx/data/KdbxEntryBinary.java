package de.soderer.utilities.kdbx.data;

import de.soderer.utilities.kdbx.utilities.Utilities;

public class KdbxEntryBinary {
	private String key;
	private Integer refID = null;
	private byte[] compressedData;

	/**
	 * Key name of this binary. Mostly a filename
	 */
	public String getKey() {
		return key;
	}

	/**
	 * Key name of this binary. Mostly a filename
	 */
	public void setKey(final String key) {
		this.key = key;
	}

	public KdbxEntryBinary withKey(final String newKey) {
		setKey(newKey);
		return this;
	}

	/**
	 * Unique id of this binary
	 */
	public Integer getRefId() {
		return refID;
	}

	/**
	 * Unique id of this binary
	 */
	public void setRefId(final Integer id) {
		compressedData = null;
		refID = id;
	}

	public KdbxEntryBinary withRefId(final Integer newId) {
		setRefId(newId);
		return this;
	}

	/**
	 * Data of this binary.
	 * Only a copy of the data array is returned, because the data array may be used by other references too
	 * and therefore the content of the original array may not be changed
	 * @throws Exception
	 */
	public byte[] getData() throws Exception {
		if (compressedData == null) {
			return null;
		} else {
			return Utilities.gunzip(compressedData);
		}
	}

	/**
	 * Data of this binary.
	 */
	public void setCompressedData(final byte[] compressedData) {
		refID = null;
		this.compressedData = compressedData;
	}

	public KdbxEntryBinary withCompressedData(final byte[] newCompressedData) {
		setCompressedData(newCompressedData);
		return this;
	}

	/**
	 * Data of this binary.
	 * @throws Exception
	 */
	public void setData(final byte[] data) throws Exception {
		refID = null;
		compressedData = Utilities.gzip(data);
	}

	public KdbxEntryBinary withData(final byte[] newData) throws Exception {
		setData(newData);
		return this;
	}
}
