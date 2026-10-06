package de.soderer.utilities.kdbx.data;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * UUID of groups, entries, icons and other objects of a KeePass database: 16 bytes, stored base64 encoded in the XML payload.
 */
public class KdbxUUID {
	/**
	 * The 16 bytes of the UUID.
	 */
	private final byte[] data;

	/**
	 * Creates a random UUID.
	 */
	public KdbxUUID() {
		data = new byte[16];
		new SecureRandom().nextBytes(data);
	}

	/**
	 * Creates a UUID from its bytes.
	 *
	 * @param data the 16 bytes of the UUID, which are copied
	 * @throws IllegalArgumentException if the data is null or has not 16 bytes
	 */
	public KdbxUUID(final byte[] data) {
		if (data == null) {
			throw new IllegalArgumentException("UUID data must not be null");
		} else if (data.length != 16) {
			throw new IllegalArgumentException("UUID must have a length of 16 bytes, but had " + data.length);
		} else {
			// Copy the data, so later changes of the given array do not change this UUID
			this.data = data.clone();
		}
	}

	/**
	 * Creates a UUID from its hexadecimal representation.
	 *
	 * @param hexString 32 hexadecimal characters
	 * @return the UUID
	 * @throws IllegalArgumentException if the text is no valid UUID
	 */
	public static KdbxUUID fromHex(final String hexString) {
		try {
			return new KdbxUUID(Utilities.fromHexString(hexString));
		} catch (final Exception e) {
			throw new IllegalArgumentException("Invalid hex string value for UUID: " + hexString, e);
		}
	}

	/**
	 * Creates a UUID from its base64 representation.
	 *
	 * @param base64String base64 text of the 16 bytes
	 * @return the UUID or null for a blank text
	 * @throws IllegalArgumentException if the text is no valid UUID
	 */
	public static KdbxUUID fromBase64(final String base64String) {
		if (Utilities.isBlank(base64String)) {
			return null;
		} else {
			try {
				final byte[] uuidBytes = Base64.getDecoder().decode(base64String);
				return new KdbxUUID(uuidBytes);
			} catch (final Exception e) {
				throw new IllegalArgumentException("Invalid base64 string value for UUID: " + base64String, e);
			}
		}
	}

	/**
	 * Returns the base64 representation of the UUID bytes.
	 *
	 * @return the base64 text
	 */
	public String toBase64() {
		return Base64.getEncoder().encodeToString(data);
	}

	@Override
	public boolean equals(final Object other) {
		if (other instanceof KdbxUUID) {
			final KdbxUUID otherUuid = (KdbxUUID) other;
			return Arrays.equals(otherUuid.data, data);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(data);
	}

	@Override
	public String toString() {
		return toHex();
	}

	/**
	 * Returns the hexadecimal representation of the UUID bytes.
	 *
	 * @return 32 hexadecimal characters
	 */
	public String toHex() {
		return Utilities.toHexString(data, "");
	}
}
