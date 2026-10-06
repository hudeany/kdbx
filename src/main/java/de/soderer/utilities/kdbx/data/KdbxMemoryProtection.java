package de.soderer.utilities.kdbx.data;

/**
 * Settings, which standard fields of entries are written as protected values (encrypted with the inner stream cipher within the payload).
 */
public class KdbxMemoryProtection {
	/**
	 * Whether the title of entries is protected.
	 */
	private boolean protectTitle;
	/**
	 * Whether the user name of entries is protected.
	 */
	private boolean protectUserName;
	/**
	 * Whether the password of entries is protected.
	 */
	private boolean protectPassword = true;
	/**
	 * Whether the URL of entries is protected.
	 */
	private boolean protectURL;
	/**
	 * Whether the notes of entries are protected.
	 */
	private boolean protectNotes;

	/**
	 * Creates memory protection settings with the KeePass defaults: only passwords are protected.
	 */
	public KdbxMemoryProtection() {
		// nothing to do
	}

	/**
	 * Sets whether the title of entries is protected.
	 *
	 * @param protectTitle whether the title of entries is protected
	 */
	public void setProtectTitle(final boolean protectTitle) {
		this.protectTitle = protectTitle;
	}

	/**
	 * Sets whether the title of entries is protected and returns this object for method chaining.
	 *
	 * @param newProtectTitle whether the title of entries is protected
	 * @return this object
	 */
	public KdbxMemoryProtection withProtectTitle(final boolean newProtectTitle) {
		setProtectTitle(newProtectTitle);
		return this;
	}

	/**
	 * Returns whether the title of entries is protected.
	 *
	 * @return whether the title of entries is protected
	 */
	public boolean isProtectTitle() {
		return protectTitle;
	}

	/**
	 * Sets whether the user name of entries is protected.
	 *
	 * @param protectUserName whether the user name of entries is protected
	 */
	public void setProtectUserName(final boolean protectUserName) {
		this.protectUserName = protectUserName;
	}

	/**
	 * Sets whether the user name of entries is protected and returns this object for method chaining.
	 *
	 * @param newProtectUserName whether the user name of entries is protected
	 * @return this object
	 */
	public KdbxMemoryProtection withProtectUserName(final boolean newProtectUserName) {
		setProtectUserName(newProtectUserName);
		return this;
	}

	/**
	 * Returns whether the user name of entries is protected.
	 *
	 * @return whether the user name of entries is protected
	 */
	public boolean isProtectUserName() {
		return protectUserName;
	}

	/**
	 * Sets whether the password of entries is protected.
	 *
	 * @param protectPassword whether the password of entries is protected
	 */
	public void setProtectPassword(final boolean protectPassword) {
		this.protectPassword = protectPassword;
	}

	/**
	 * Sets whether the password of entries is protected and returns this object for method chaining.
	 *
	 * @param newProtectPassword whether the password of entries is protected
	 * @return this object
	 */
	public KdbxMemoryProtection withProtectPassword(final boolean newProtectPassword) {
		setProtectPassword(newProtectPassword);
		return this;
	}

	/**
	 * Returns whether the password of entries is protected.
	 *
	 * @return whether the password of entries is protected
	 */
	public boolean isProtectPassword() {
		return protectPassword;
	}

	/**
	 * Sets whether the URL of entries is protected.
	 *
	 * @param protectURL whether the URL of entries is protected
	 */
	public void setProtectURL(final boolean protectURL) {
		this.protectURL = protectURL;
	}

	/**
	 * Sets whether the URL of entries is protected and returns this object for method chaining.
	 *
	 * @param newProtectURL whether the URL of entries is protected
	 * @return this object
	 */
	public KdbxMemoryProtection withProtectURL(final boolean newProtectURL) {
		setProtectURL(newProtectURL);
		return this;
	}

	/**
	 * Returns whether the URL of entries is protected.
	 *
	 * @return whether the URL of entries is protected
	 */
	public boolean isProtectURL() {
		return protectURL;
	}

	/**
	 * Sets whether the notes of entries are protected.
	 *
	 * @param protectNotes whether the notes of entries are protected
	 */
	public void setProtectNotes(final boolean protectNotes) {
		this.protectNotes = protectNotes;
	}

	/**
	 * Sets whether the notes of entries are protected and returns this object for method chaining.
	 *
	 * @param newProtectNotes whether the notes of entries are protected
	 * @return this object
	 */
	public KdbxMemoryProtection withProtectNotes(final boolean newProtectNotes) {
		setProtectNotes(newProtectNotes);
		return this;
	}

	/**
	 * Returns whether the notes of entries are protected.
	 *
	 * @return whether the notes of entries are protected
	 */
	public boolean isProtectNotes() {
		return protectNotes;
	}
}
