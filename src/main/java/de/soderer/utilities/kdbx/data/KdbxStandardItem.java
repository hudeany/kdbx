package de.soderer.utilities.kdbx.data;

/**
 * Standard items of a KeePass entry and their keys in the item map.
 */
public enum KdbxStandardItem {
	/** Title of the entry. */
	TITLE("Title"),
	/** User name of the entry. */
	USERNAME("UserName"),
	/** Password of the entry. */
	PASSWORD("Password"),
	/** URL of the entry. */
	URL("URL"),
	/** Notes of the entry. */
	NOTES("Notes");

	/**
	 * Key of this item in the item map.
	 */
	private final String key;

	/**
	 * Creates a standard item.
	 *
	 * @param key key of this item in the item map
	 */
	KdbxStandardItem(final String key) {
		this.key = key;
	}

	/**
	 * Returns the key of this item in the item map.
	 *
	 * @return the key of this item in the item map
	 */
	public String getKey() {
		return key;
	}

	/**
	 * Returns the standard item for a key.
	 *
	 * @param key key of the item (case-sensitive)
	 * @return the standard item or null, if the key is not a standard item key
	 */
	public static KdbxStandardItem getByKey(final String key) {
		for (final KdbxStandardItem item : values()) {
			if (item.key.equals(key)) {
				return item;
			}
		}
		return null;
	}

	/**
	 * Returns whether a key is the key of a standard item.
	 *
	 * @param key key of the item (case-sensitive)
	 * @return true if the key is the key of a standard item
	 */
	public static boolean isStandardItemKey(final String key) {
		return getByKey(key) != null;
	}
}
