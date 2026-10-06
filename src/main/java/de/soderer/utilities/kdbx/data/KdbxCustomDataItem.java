package de.soderer.utilities.kdbx.data;

import java.time.ZonedDateTime;

/**
 * Custom data item: key/value data of plugins and applications, stored in the meta data, groups or entries.
 */
public class KdbxCustomDataItem {
	/**
	 * Key of the item.
	 */
	private String key;
	/**
	 * Value of the item.
	 */
	private String value;
	/**
	 * Time of the last modification of the item (KDBX 4.1 and higher), or null.
	 */
	private ZonedDateTime lastModificationTime = null;

	/**
	 * Creates an empty custom data item.
	 */
	public KdbxCustomDataItem() {
		// nothing to do
	}

	/**
	 * Sets the key of the item.
	 *
	 * @param key the key of the item
	 */
	public void setKey(final String key) {
		this.key = key;
	}

	/**
	 * Sets the key of the item and returns this object for method chaining.
	 *
	 * @param newKey the key of the item
	 * @return this object
	 */
	public KdbxCustomDataItem withKey(final String newKey) {
		setKey(newKey);
		return this;
	}

	/**
	 * Returns the key of the item.
	 *
	 * @return the key of the item
	 */
	public String getKey() {
		return key;
	}

	/**
	 * Sets the value of the item.
	 *
	 * @param value the value of the item
	 */
	public void setValue(final String value) {
		this.value = value;
	}

	/**
	 * Sets the value of the item and returns this object for method chaining.
	 *
	 * @param newValue the value of the item
	 * @return this object
	 */
	public KdbxCustomDataItem withValue(final String newValue) {
		setValue(newValue);
		return this;
	}

	/**
	 * Returns the value of the item.
	 *
	 * @return the value of the item
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Sets the time of the last modification of the item (KDBX 4.1 and higher), or null.
	 *
	 * @param lastModificationTime the time of the last modification of the item (KDBX 4.1 and higher), or null
	 */
	public void setLastModificationTime(final ZonedDateTime lastModificationTime) {
		this.lastModificationTime = lastModificationTime;
	}

	/**
	 * Sets the time of the last modification of the item (KDBX 4.1 and higher), or null and returns this object for method chaining.
	 *
	 * @param newLastModificationTime the time of the last modification of the item (KDBX 4.1 and higher), or null
	 * @return this object
	 */
	public KdbxCustomDataItem withLastModificationTime(final ZonedDateTime newLastModificationTime) {
		setLastModificationTime(newLastModificationTime);
		return this;
	}

	/**
	 * Returns the time of the last modification of the item (KDBX 4.1 and higher), or null.
	 *
	 * @return the time of the last modification of the item (KDBX 4.1 and higher), or null
	 */
	public ZonedDateTime getLastModificationTime() {
		return lastModificationTime;
	}
}
