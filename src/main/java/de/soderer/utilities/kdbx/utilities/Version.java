package de.soderer.utilities.kdbx.utilities;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Version number consisting of major, minor and micro number, like "1.2.3".
 * Versions are ordered numerically by major, then minor, then micro number (so "19.0.10" is newer than "19.0.9").
 */
public class Version implements Comparable<Version> {

	/** Pattern of a full version string */
	private static final Pattern VERSIONPATTERN = Pattern.compile("^(\\d+)\\.(\\d+)\\.(\\d+)$");

	/** Pattern to find a version within a text */
	private static final Pattern VERSION_IN_TEXT_PATTERN = Pattern.compile("\\d+\\.\\d+\\.\\d+");

	/** The major version number. */
	private final int majorVersionNumber;

	/** The minor version number. */
	private final int minorVersionNumber;

	/** The micro version number. */
	private final int microVersionNumber;

	/**
	 * Create a version from its parts.
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
	 * Parse a version string like "1.2.3".
	 *
	 * @param versionString
	 *            version string with exactly three numeric parts separated by dots
	 * @throws Exception
	 *             if the string is null or not a valid version string, or a part exceeds the int range
	 */
	public Version(final String versionString) throws Exception {
		final Matcher matcher = versionString == null ? null : VERSIONPATTERN.matcher(versionString);
		if (matcher != null && matcher.find()) {
			majorVersionNumber = Integer.parseInt(matcher.group(1));
			minorVersionNumber = Integer.parseInt(matcher.group(2));
			microVersionNumber = Integer.parseInt(matcher.group(3));
		} else {
			throw new Exception("Invalid version number");
		}
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

	/**
	 * Version string like "1.2.3".
	 */
	@Override
	public String toString() {
		return new StringBuilder().append(majorVersionNumber).append(".").append(minorVersionNumber).append(".").append(microVersionNumber).toString();
	}

	/**
	 * Gets the first full version (three numeric parts) found in a text.
	 *
	 * @param data
	 *            text to search, may be null
	 * @return the first version found in the text, or null if there is none
	 */
	public static Version getFirstFullVersionNumberFromText(final String data) {
		if (Utilities.isBlank(data)) {
			return null;
		} else {
			final Matcher matcher = VERSION_IN_TEXT_PATTERN.matcher(data);
			while (matcher.find()) {
				try {
					return new Version(matcher.group());
				} catch (@SuppressWarnings("unused") final Exception e) {
					// A part exceeds the int range (e.g. a build timestamp), so a later version in the text may still be valid
				}
			}
			return null;
		}
	}

	/**
	 * Compare this version to another version. A null version is treated as older than any version.
	 *
	 * @return +1 if this version is newer than otherVersion, 0 if both are equal, -1 if this version is older
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

	/**
	 * Two versions are equal if all three version numbers are equal (consistent with {@link #compareTo(Version)}).
	 */
	@Override
	public boolean equals(final Object other) {
		if (this == other) {
			return true;
		} else if (!(other instanceof Version)) {
			return false;
		} else {
			final Version otherVersion = (Version) other;
			return majorVersionNumber == otherVersion.majorVersionNumber
					&& minorVersionNumber == otherVersion.minorVersionNumber
					&& microVersionNumber == otherVersion.microVersionNumber;
		}
	}

	@Override
	public int hashCode() {
		return (majorVersionNumber * 31 + minorVersionNumber) * 31 + microVersionNumber;
	}
}
