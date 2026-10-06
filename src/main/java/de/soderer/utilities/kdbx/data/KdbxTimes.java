package de.soderer.utilities.kdbx.data;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Objects;

/**
 * Times and usage data of a group or entry.
 */
public class KdbxTimes {
	/**
	 * Time of the last modification.
	 */
	private ZonedDateTime lastModificationTime;
	/**
	 * Time of creation.
	 */
	private ZonedDateTime creationTime;
	/**
	 * Time of the last access.
	 */
	private ZonedDateTime lastAccessTime;
	/**
	 * Time of expiry, which is only effective if expiry is activated.
	 */
	private ZonedDateTime expiryTime;
	/**
	 * Whether the expiry time is activated.
	 */
	private boolean expires;
	/**
	 * Usage count.
	 */
	private int usageCount;
	/**
	 * Time of the last move to another group.
	 */
	private ZonedDateTime locationChanged;

	/**
	 * Creates times with creation time and last modification time set to now.
	 */
	public KdbxTimes() {
		creationTime = ZonedDateTime.now();
		lastModificationTime = creationTime;
	}

	/**
	 * Returns the time of the last modification.
	 *
	 * @return the time of the last modification
	 */
	public ZonedDateTime getLastModificationTime() {
		return lastModificationTime;
	}

	/**
	 * Sets the time of the last modification.
	 *
	 * @param lastModificationTime the time of the last modification
	 */
	public void setLastModificationTime(final ZonedDateTime lastModificationTime) {
		this.lastModificationTime = lastModificationTime;
	}

	/**
	 * Sets the time of the last modification and returns this object for method chaining.
	 *
	 * @param newLastModificationTime the time of the last modification
	 * @return this object
	 */
	public KdbxTimes withLastModificationTime(final ZonedDateTime newLastModificationTime) {
		setLastModificationTime(newLastModificationTime);
		return this;
	}

	/**
	 * Returns the time of creation.
	 *
	 * @return the time of creation
	 */
	public ZonedDateTime getCreationTime() {
		return creationTime;
	}

	/**
	 * Sets the time of creation.
	 *
	 * @param creationTime the time of creation
	 */
	public void setCreationTime(final ZonedDateTime creationTime) {
		this.creationTime = creationTime;
	}

	/**
	 * Sets the time of creation and returns this object for method chaining.
	 *
	 * @param newCreationTime the time of creation
	 * @return this object
	 */
	public KdbxTimes withCreationTime(final ZonedDateTime newCreationTime) {
		setCreationTime(newCreationTime);
		return this;
	}

	/**
	 * Returns the time of the last access.
	 *
	 * @return the time of the last access
	 */
	public ZonedDateTime getLastAccessTime() {
		return lastAccessTime;
	}

	/**
	 * Sets the time of the last access.
	 *
	 * @param lastAccessTime the time of the last access
	 */
	public void setLastAccessTime(final ZonedDateTime lastAccessTime) {
		this.lastAccessTime = lastAccessTime;
	}

	/**
	 * Sets the time of the last access and returns this object for method chaining.
	 *
	 * @param newLastAccessTime the time of the last access
	 * @return this object
	 */
	public KdbxTimes withLastAccessTime(final ZonedDateTime newLastAccessTime) {
		setLastAccessTime(newLastAccessTime);
		return this;
	}

	/**
	 * Returns the time of expiry, which is only effective if expiry is activated.
	 *
	 * @return the time of expiry, which is only effective if expiry is activated
	 */
	public ZonedDateTime getExpiryTime() {
		return expiryTime;
	}

	/**
	 * Sets the time of expiry, which is only effective if expiry is activated.
	 *
	 * @param expiryTime the time of expiry, which is only effective if expiry is activated
	 */
	public void setExpiryTime(final ZonedDateTime expiryTime) {
		this.expiryTime = expiryTime;
	}

	/**
	 * Sets the time of expiry, which is only effective if expiry is activated and returns this object for method chaining.
	 *
	 * @param newExpiryTime the time of expiry, which is only effective if expiry is activated
	 * @return this object
	 */
	public KdbxTimes withExpiryTime(final ZonedDateTime newExpiryTime) {
		setExpiryTime(newExpiryTime);
		return this;
	}

	/**
	 * Returns whether the expiry time is activated.
	 *
	 * @return whether the expiry time is activated
	 */
	public boolean isExpires() {
		return expires;
	}

	/**
	 * Sets whether the expiry time is activated.
	 *
	 * @param expires whether the expiry time is activated
	 */
	public void setExpires(final boolean expires) {
		this.expires = expires;
	}

	/**
	 * Sets whether the expiry time is activated and returns this object for method chaining.
	 *
	 * @param newExpires whether the expiry time is activated
	 * @return this object
	 */
	public KdbxTimes withExpires(final boolean newExpires) {
		setExpires(newExpires);
		return this;
	}

	/**
	 * Returns the usage count.
	 *
	 * @return the usage count
	 */
	public int getUsageCount() {
		return usageCount;
	}

	/**
	 * Sets the usage count.
	 *
	 * @param usageCount the usage count
	 */
	public void setUsageCount(final int usageCount) {
		this.usageCount = usageCount;
	}

	/**
	 * Sets the usage count and returns this object for method chaining.
	 *
	 * @param newUsageCount the usage count
	 * @return this object
	 */
	public KdbxTimes withUsageCount(final int newUsageCount) {
		setUsageCount(newUsageCount);
		return this;
	}

	/**
	 * Returns the time of the last move to another group.
	 *
	 * @return the time of the last move to another group
	 */
	public ZonedDateTime getLocationChanged() {
		return locationChanged;
	}

	/**
	 * Sets the time of the last move to another group.
	 *
	 * @param locationChanged the time of the last move to another group
	 */
	public void setLocationChanged(final ZonedDateTime locationChanged) {
		this.locationChanged = locationChanged;
	}

	/**
	 * Sets the time of the last move to another group and returns this object for method chaining.
	 *
	 * @param newLocationChanged the time of the last move to another group
	 * @return this object
	 */
	public KdbxTimes withLocationChanged(final ZonedDateTime newLocationChanged) {
		setLocationChanged(newLocationChanged);
		return this;
	}

	@Override
	public int hashCode() {
		// Use the instants, because equals compares the instants independent of the time zone
		return Objects.hash(toInstant(creationTime), expires, toInstant(expiryTime), toInstant(lastAccessTime), toInstant(lastModificationTime), toInstant(locationChanged), usageCount);
	}

	/**
	 * Converts a time to its instant.
	 *
	 * @param zonedDateTime the time or null
	 * @return the instant or null
	 */
	private static Instant toInstant(final ZonedDateTime zonedDateTime) {
		return zonedDateTime == null ? null : zonedDateTime.toInstant();
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

	/**
	 * Compares two times by their instants, independent of the time zone.
	 *
	 * @param zonedDateTime1 first time or null
	 * @param zonedDateTime2 second time or null
	 * @return true for the same instant or both null
	 */
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
