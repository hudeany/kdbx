package de.soderer.utilities.kdbx.data;

import java.time.ZonedDateTime;

public class KdbxCustomDataItem {
	public String key;
	public String value;
	public ZonedDateTime lastModificationTime = null;

	public void setKey(final String key) {
		this.key = key;
	}

	public KdbxCustomDataItem withKey(final String newKey) {
		setKey(newKey);
		return this;
	}

	public String getKey() {
		return key;
	}

	public void setValue(final String value) {
		this.value = value;
	}

	public KdbxCustomDataItem withValue(final String newValue) {
		setValue(newValue);
		return this;
	}

	public String getValue() {
		return value;
	}

	public void setLastModificationTime(final ZonedDateTime lastModificationTime) {
		this.lastModificationTime = lastModificationTime;
	}

	public KdbxCustomDataItem withLastModificationTime(final ZonedDateTime newLastModificationTime) {
		setLastModificationTime(newLastModificationTime);
		return this;
	}

	public ZonedDateTime getLastModificationTime() {
		return lastModificationTime;
	}
}
