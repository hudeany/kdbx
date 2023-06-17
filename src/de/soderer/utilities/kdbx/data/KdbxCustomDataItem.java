package de.soderer.utilities.kdbx.data;

import java.time.ZonedDateTime;

public class KdbxCustomDataItem {
	public String key;
	public String value;
	public ZonedDateTime lastModificationTime = null;

	public String getKey() {
		return key;
	}

	public void setKey(final String key) {
		this.key = key;
	}

	public String getValue() {
		return value;
	}

	public void setValue(final String value) {
		this.value = value;
	}

	public ZonedDateTime getLastModificationTime() {
		return lastModificationTime;
	}

	public void setLastModificationTime(final ZonedDateTime lastModificationTime) {
		this.lastModificationTime = lastModificationTime;
	}
}
