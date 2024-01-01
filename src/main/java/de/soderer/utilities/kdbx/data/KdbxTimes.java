package de.soderer.utilities.kdbx.data;

import java.time.ZonedDateTime;
import java.util.Objects;

public class KdbxTimes {
	public ZonedDateTime lastModificationTime;
	public ZonedDateTime creationTime;
	public ZonedDateTime lastAccessTime;
	public ZonedDateTime expiryTime;
	public boolean expires;
	public int usageCount;
	public ZonedDateTime locationChanged;

	public KdbxTimes() {
		creationTime = ZonedDateTime.now();
		lastModificationTime = creationTime;
	}

	public ZonedDateTime getLastModificationTime() {
		return lastModificationTime;
	}

	public KdbxTimes setLastModificationTime(final ZonedDateTime lastModificationTime) {
		this.lastModificationTime = lastModificationTime;
		return this;
	}

	public ZonedDateTime getCreationTime() {
		return creationTime;
	}

	public KdbxTimes setCreationTime(final ZonedDateTime creationTime) {
		this.creationTime = creationTime;
		return this;
	}

	public ZonedDateTime getLastAccessTime() {
		return lastAccessTime;
	}

	public KdbxTimes setLastAccessTime(final ZonedDateTime lastAccessTime) {
		this.lastAccessTime = lastAccessTime;
		return this;
	}

	public ZonedDateTime getExpiryTime() {
		return expiryTime;
	}

	public KdbxTimes setExpiryTime(final ZonedDateTime expiryTime) {
		this.expiryTime = expiryTime;
		return this;
	}

	public boolean isExpires() {
		return expires;
	}

	public KdbxTimes setExpires(final boolean expires) {
		this.expires = expires;
		return this;
	}

	public int getUsageCount() {
		return usageCount;
	}

	public KdbxTimes setUsageCount(final int usageCount) {
		this.usageCount = usageCount;
		return this;
	}

	public ZonedDateTime getLocationChanged() {
		return locationChanged;
	}

	public KdbxTimes setLocationChanged(final ZonedDateTime locationChanged) {
		this.locationChanged = locationChanged;
		return this;
	}

	@Override
	public int hashCode() {
		return Objects.hash(creationTime, expires, expiryTime, lastAccessTime, lastModificationTime, locationChanged, usageCount);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (getClass() != obj.getClass()) {
			return false;
		} else {
			KdbxTimes other = (KdbxTimes) obj;
			return expires == other.expires
					&& usageCount == other.usageCount
					&& timeEquals(creationTime, other.creationTime)
					&& timeEquals(expiryTime, other.expiryTime)
					&& timeEquals(lastAccessTime, other.lastAccessTime)
					&& timeEquals(lastModificationTime, other.lastModificationTime)
					&& timeEquals(locationChanged, other.locationChanged);
		}
	}

	private boolean timeEquals(ZonedDateTime zonedDateTime1, ZonedDateTime zonedDateTime2) {
		if (zonedDateTime1 == zonedDateTime2) {
			return true;
		} else if (zonedDateTime1 == null || zonedDateTime2 == null) {
			return false;
		} else {
			return zonedDateTime1.isEqual(zonedDateTime2);
		}
	}
}
