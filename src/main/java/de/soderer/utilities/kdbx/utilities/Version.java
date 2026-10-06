package de.soderer.utilities.kdbx.utilities;

/**
 * Version number with major, minor and micro part, e.g. the KDBX data format version.
 */
public class Version implements Comparable<Version> {
	/** The major version number. */
	private int majorVersionNumber;

	/** The minor version number. */
	private int minorVersionNumber;

	/** The micro version number. */
	private int microVersionNumber;

	/**
	 * The Constructor.
	 *
	 * @param majorVersionNumber
	 *            the major version number
	 * @param minorVersionNumber
	 *            the minor version number
	 * @param microVersionNumber
	 *            the micro version number
	 */
	public Version(final int majorVersionNumber, final int minorVersionNumber, final int microVersionNumber) {
		this.majorVersionNumber = majorVersionNumber;
		this.minorVersionNumber = minorVersionNumber;
		this.microVersionNumber = microVersionNumber;
	}

	/**
	 * Gets the major version number.
	 *
	 * @return the major version number
	 */
	public int getMajorVersionNumber() {
		return majorVersionNumber;
	}

	/**
	 * Gets the minor version number.
	 *
	 * @return the minor version number
	 */
	public int getMinorVersionNumber() {
		return minorVersionNumber;
	}

	/**
	 * Gets the micro version number.
	 *
	 * @return the micro version number
	 */
	public int getMicroVersionNumber() {
		return microVersionNumber;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return new StringBuilder().append(majorVersionNumber).append(".").append(minorVersionNumber).append(".").append(microVersionNumber).toString();
	}

	/**
	 * Compares the version numbers.
	 *
	 * @param otherVersion the other version or null
	 * @return 1 if this version is greater (or the other version is null), 0 for equal versions, -1 if this version is lower
	 */
	@Override
	public int compareTo(final Version otherVersion) {
		if (otherVersion == null || majorVersionNumber > otherVersion.getMajorVersionNumber()) {
			return 1;
		} else if (majorVersionNumber == otherVersion.getMajorVersionNumber()) {
			if (minorVersionNumber > otherVersion.getMinorVersionNumber()) {
				return 1;
			} else if (minorVersionNumber == otherVersion.getMinorVersionNumber()) {
				if (microVersionNumber > otherVersion.getMicroVersionNumber()) {
					return 1;
				} else if (microVersionNumber == otherVersion.getMicroVersionNumber()) {
					return 0;
				} else {
					return -1;
				}
			} else {
				return -1;
			}
		} else {
			return -1;
		}
	}

	@Override
	public boolean equals(final Object other) {
		if (this == other) {
			return true;
		} else if (!(other instanceof Version)) {
			return false;
		} else {
			return compareTo((Version) other) == 0;
		}
	}

	@Override
	public int hashCode() {
		return java.util.Objects.hash(majorVersionNumber, minorVersionNumber, microVersionNumber);
	}
}
