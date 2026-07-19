package de.soderer.utilities.kdbx.data;

public class KdbxMemoryProtection {
	private boolean protectTitle;
	private boolean protectUserName;
	private boolean protectPassword = true;
	private boolean protectURL;
	private boolean protectNotes;

	public void setProtectTitle(final boolean protectTitle) {
		this.protectTitle = protectTitle;
	}

	public KdbxMemoryProtection withProtectTitle(final boolean newProtectTitle) {
		setProtectTitle(newProtectTitle);
		return this;
	}

	public boolean isProtectTitle() {
		return protectTitle;
	}

	public void setProtectUserName(final boolean protectUserName) {
		this.protectUserName = protectUserName;
	}

	public KdbxMemoryProtection withProtectUserName(final boolean newProtectUserName) {
		setProtectUserName(newProtectUserName);
		return this;
	}

	public boolean isProtectUserName() {
		return protectUserName;
	}

	public void setProtectPassword(final boolean protectPassword) {
		this.protectPassword = protectPassword;
	}

	public KdbxMemoryProtection withProtectPassword(final boolean newProtectPassword) {
		setProtectPassword(newProtectPassword);
		return this;
	}

	public boolean isProtectPassword() {
		return protectPassword;
	}

	public void setProtectURL(final boolean protectURL) {
		this.protectURL = protectURL;
	}

	public KdbxMemoryProtection withProtectURL(final boolean newProtectURL) {
		setProtectURL(newProtectURL);
		return this;
	}

	public boolean isProtectURL() {
		return protectURL;
	}

	public void setProtectNotes(final boolean protectNotes) {
		this.protectNotes = protectNotes;
	}

	public KdbxMemoryProtection withProtectNotes(final boolean newProtectNotes) {
		setProtectNotes(newProtectNotes);
		return this;
	}

	public boolean isProtectNotes() {
		return protectNotes;
	}
}
