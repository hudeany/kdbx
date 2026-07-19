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

	public void setLastModificationTime(final ZonedDateTime lastModificationTime) {
		this.lastModificationTime = lastModificationTime;
	}

	public KdbxTimes withLastModificationTime(final ZonedDateTime newLastModificationTime) {
		setLastModificationTime(newLastModificationTime);
		return this;
	}

	public ZonedDateTime getCreationTime() {
		return creationTime;
	}

	public void setCreationTime(final ZonedDateTime creationTime) {
		this.creationTime = creationTime;
	}

	public KdbxTimes withCreationTime(final ZonedDateTime newCreationTime) {
		setCreationTime(newCreationTime);
		return this;
	}

	public ZonedDateTime getLastAccessTime() {
		return lastAccessTime;
	}

	public void setLastAccessTime(final ZonedDateTime lastAccessTime) {
		this.lastAccessTime = lastAccessTime;
	}

	public KdbxTimes withLastAccessTime(final ZonedDateTime newLastAccessTime) {
		setLastAccessTime(newLastAccessTime);
		return this;
	}

	public ZonedDateTime getExpiryTime() {
		return expiryTime;
	}

	public void setExpiryTime(final ZonedDateTime expiryTime) {
		this.expiryTime = expiryTime;
	}

	public KdbxTimes withExpiryTime(final ZonedDateTime newExpiryTime) {
		setExpiryTime(newExpiryTime);
		return this;
	}

	public boolean isExpires() {
		return expires;
	}

	public void setExpires(final boolean expires) {
		this.expires = expires;
	}

	public KdbxTimes withExpires(final boolean newExpires) {
		setExpires(newExpires);
		return this;
	}

	public int getUsageCount() {
		return usageCount;
	}

	public void setUsageCount(final int usageCount) {
		this.usageCount = usageCount;
	}

	public KdbxTimes withUsageCount(final int newUsageCount) {
		setUsageCount(newUsageCount);
		return this;
	}

	public ZonedDateTime getLocationChanged() {
		return locationChanged;
	}

	public void setLocationChanged(final ZonedDateTime locationChanged) {
		this.locationChanged = locationChanged;
	}

	public KdbxTimes withLocationChanged(final ZonedDateTime newLocationChanged) {
		setLocationChanged(newLocationChanged);
		return this;
	}

	@Override
	public int hashCode() {
		return Objects.hash(creationTime, expires, expiryTime, lastAccessTime, lastModificationTime, locationChanged, usageCount);
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (getClass() != obj.getClass()) {
			return false;
		} else {
			final KdbxTimes other = (KdbxTimes) obj;
			return expires == other.expires
					&& usageCount == other.usageCount
					&& timeEquals(creationTime, other.creationTime)
					&& timeEquals(expiryTime, other.expiryTime)
					&& timeEquals(lastAccessTime, other.lastAccessTime)
					&& timeEquals(lastModificationTime, other.lastModificationTime)
					&& timeEquals(locationChanged, other.locationChanged);
		}
	}

	private static boolean timeEquals(final ZonedDateTime zonedDateTime1, final ZonedDateTime zonedDateTime2) {
		if (zonedDateTime1 == zonedDateTime2) {
			return true;
		} else if (zonedDateTime1 == null || zonedDateTime2 == null) {
			return false;
		} else {
			return zonedDateTime1.isEqual(zonedDateTime2);
		}
	}
}
