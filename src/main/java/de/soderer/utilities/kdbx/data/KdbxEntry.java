package de.soderer.utilities.kdbx.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

/**
 * Entry of a KeePass database with its items (title, user name, password, URL, notes and custom fields), attachments and history.
 * <p>
 * The standard items are stored with the keys "Title", "UserName", "Password", "URL" and "Notes".
 */
public class KdbxEntry {
	/**
	 * UUID of this entry.
	 */
	private KdbxUUID uuid;
	/**
	 * Id of the standard icon of this entry (see {@link KdbxConstants.KdbxStandardIcon}), or null.
	 */
	private Integer iconID;
	/**
	 * UUID of the custom icon of this entry (see {@link KdbxMeta#getCustomIcons()}), or null.
	 */
	private KdbxUUID customIconUuid;
	/**
	 * Foreground color of this entry in the GUI as HTML color text, or null.
	 */
	private String foregroundColor;
	/**
	 * Background color of this entry in the GUI as HTML color text, or null.
	 */
	private String backgroundColor;
	/**
	 * URL override (command line) for opening the URL of this entry, or null.
	 */
	private String overrideURL;
	/**
	 * Tags of this entry, separated by "," or ";".
	 */
	private String tags;
	/**
	 * Times and usage data of this entry.
	 */
	private KdbxTimes times = new KdbxTimes();
	/**
	 * Items (key/value strings) of this entry.
	 */
	private Map<String, Object> items = new LinkedHashMap<>();
	/**
	 * Whether auto-type is enabled for this entry.
	 */
	private boolean autoTypeEnabled = false;
	/**
	 * Auto-type data transfer obfuscation setting of this entry ("0" for none, "1" for two-channel auto-type obfuscation).
	 */
	private String autoTypeDataTransferObfuscation;
	/**
	 * Default auto-type keystroke sequence of this entry, or null to use the sequence of the group.
	 */
	private String autoTypeDefaultSequence;
	/**
	 * Window title pattern of the auto-type association of this entry.
	 */
	private String autoTypeAssociationWindow;
	/**
	 * Keystroke sequence of the auto-type association of this entry.
	 */
	private String autoTypeAssociationKeystrokeSequence;
	/**
	 * Custom data items of this entry (KDBX 4.x).
	 */
	private List<KdbxCustomDataItem> customData;
	/**
	 * History entries (former versions) of this entry.
	 */
	private final List<KdbxEntry> history = new ArrayList<>();
	/**
	 * Attachments of this entry.
	 */
	private final List<KdbxEntryBinary> binaries = new ArrayList<>();
	/**
	 * Keys of items, which are written as protected values in addition to those of the memory protection settings.
	 */
	private final Set<String> protectedItemKeys = new LinkedHashSet<>();

	/**
	 * Creates an empty entry. A random UUID is created on first access, if none is set.
	 */
	public KdbxEntry() {
		// nothing to do
	}

	/**
	 * Sets the UUID of this entry.
	 *
	 * @param uuid the UUID of this entry
	 */
	public void setUuid(final KdbxUUID uuid) {
		this.uuid = uuid;
	}

	/**
	 * Sets the UUID of this entry and returns this object for method chaining.
	 *
	 * @param newUuid the UUID of this entry
	 * @return this object
	 */
	public KdbxEntry withUuid(final KdbxUUID newUuid) {
		setUuid(newUuid);
		return this;
	}

	/**
	 * Returns the UUID of this entry. A random UUID is created, if none was set.
	 *
	 * @return the UUID of this entry
	 */
	public KdbxUUID getUuid() {
		if (uuid == null) {
			uuid = new KdbxUUID();
		}
		return uuid;
	}

	/**
	 * Sets the title of this entry (item "Title").
	 *
	 * @param title the title of this entry (item "Title")
	 */
	public void setTitle(final String title) {
		items.put("Title", title);
	}

	/**
	 * Sets the title of this entry (item "Title") and returns this object for method chaining.
	 *
	 * @param newTitle the title of this entry (item "Title")
	 * @return this object
	 */
	public KdbxEntry withTitle(final String newTitle) {
		setTitle(newTitle);
		return this;
	}

	/**
	 * Returns the title of this entry (item "Title").
	 *
	 * @return the title of this entry (item "Title")
	 */
	public String getTitle() {
		return (String) items.get("Title");
	}

	/**
	 * Sets the user name of this entry (item "UserName").
	 *
	 * @param username the user name of this entry (item "UserName")
	 */
	public void setUsername(final String username) {
		items.put("UserName", username);
	}

	/**
	 * Sets the user name of this entry (item "UserName") and returns this object for method chaining.
	 *
	 * @param newUsername the user name of this entry (item "UserName")
	 * @return this object
	 */
	public KdbxEntry withUsername(final String newUsername) {
		setUsername(newUsername);
		return this;
	}

	/**
	 * Returns the user name of this entry (item "UserName").
	 *
	 * @return the user name of this entry (item "UserName")
	 */
	public String getUsername() {
		return (String) items.get("UserName");
	}

	/**
	 * Sets the password of this entry (item "Password").
	 *
	 * @param password the password of this entry (item "Password")
	 */
	public void setPassword(final String password) {
		items.put("Password", password);
	}

	/**
	 * Sets the password of this entry (item "Password") and returns this object for method chaining.
	 *
	 * @param newPassword the password of this entry (item "Password")
	 * @return this object
	 */
	public KdbxEntry withPassword(final String newPassword) {
		setPassword(newPassword);
		return this;
	}

	/**
	 * Returns the password of this entry (item "Password").
	 *
	 * @return the password of this entry (item "Password")
	 */
	public String getPassword() {
		return (String) items.get("Password");
	}

	/**
	 * Sets the URL of this entry (item "URL").
	 *
	 * @param url the URL of this entry (item "URL")
	 */
	public void setUrl(final String url) {
		items.put("URL", url);
	}

	/**
	 * Sets the URL of this entry (item "URL") and returns this object for method chaining.
	 *
	 * @param newUrl the URL of this entry (item "URL")
	 * @return this object
	 */
	public KdbxEntry withUrl(final String newUrl) {
		setUrl(newUrl);
		return this;
	}

	/**
	 * Returns the URL of this entry (item "URL").
	 *
	 * @return the URL of this entry (item "URL")
	 */
	public String getUrl() {
		return (String) items.get("URL");
	}

	/**
	 * Sets the notes of this entry (item "Notes").
	 *
	 * @param notes the notes of this entry (item "Notes")
	 */
	public void setNotes(final String notes) {
		items.put("Notes", notes);
	}

	/**
	 * Sets the notes of this entry (item "Notes") and returns this object for method chaining.
	 *
	 * @param newNotes the notes of this entry (item "Notes")
	 * @return this object
	 */
	public KdbxEntry withNotes(final String newNotes) {
		setNotes(newNotes);
		return this;
	}

	/**
	 * Returns the notes of this entry (item "Notes").
	 *
	 * @return the notes of this entry (item "Notes")
	 */
	public String getNotes() {
		return (String) items.get("Notes");
	}

	/**
	 * Sets the id of the standard icon of this entry (see {@link KdbxConstants.KdbxStandardIcon}), or null.
	 *
	 * @param iconID the id of the standard icon of this entry (see {@link KdbxConstants.KdbxStandardIcon}), or null
	 */
	public void setIconID(final Integer iconID) {
		this.iconID = iconID;
	}

	/**
	 * Sets the id of the standard icon of this entry (see {@link KdbxConstants.KdbxStandardIcon}), or null and returns this object for method chaining.
	 *
	 * @param newIconID the id of the standard icon of this entry (see {@link KdbxConstants.KdbxStandardIcon}), or null
	 * @return this object
	 */
	public KdbxEntry withIconID(final Integer newIconID) {
		setIconID(newIconID);
		return this;
	}

	/**
	 * Returns the id of the standard icon of this entry (see {@link KdbxConstants.KdbxStandardIcon}), or null.
	 *
	 * @return the id of the standard icon of this entry (see {@link KdbxConstants.KdbxStandardIcon}), or null
	 */
	public Integer getIconID() {
		return iconID;
	}

	/**
	 * Sets the UUID of the custom icon of this entry (see {@link KdbxMeta#getCustomIcons()}), or null.
	 *
	 * @param customIconUuid the UUID of the custom icon of this entry (see {@link KdbxMeta#getCustomIcons()}), or null
	 */
	public void setCustomIconUuid(final KdbxUUID customIconUuid) {
		this.customIconUuid = customIconUuid;
	}

	/**
	 * Sets the UUID of the custom icon of this entry (see {@link KdbxMeta#getCustomIcons()}), or null and returns this object for method chaining.
	 *
	 * @param newCustomIconUuid the UUID of the custom icon of this entry (see {@link KdbxMeta#getCustomIcons()}), or null
	 * @return this object
	 */
	public KdbxEntry withCustomIconUuid(final KdbxUUID newCustomIconUuid) {
		setCustomIconUuid(newCustomIconUuid);
		return this;
	}

	/**
	 * Returns the UUID of the custom icon of this entry (see {@link KdbxMeta#getCustomIcons()}), or null.
	 *
	 * @return the UUID of the custom icon of this entry (see {@link KdbxMeta#getCustomIcons()}), or null
	 */
	public KdbxUUID getCustomIconUuid() {
		return customIconUuid;
	}

	/**
	 * Sets the foreground color of this entry in the GUI as HTML color text, or null.
	 *
	 * @param foregroundColor the foreground color of this entry in the GUI as HTML color text, or null
	 */
	public void setForegroundColor(final String foregroundColor) {
		this.foregroundColor = foregroundColor;
	}

	/**
	 * Sets the foreground color of this entry in the GUI as HTML color text, or null and returns this object for method chaining.
	 *
	 * @param newForegroundColor the foreground color of this entry in the GUI as HTML color text, or null
	 * @return this object
	 */
	public KdbxEntry withForegroundColor(final String newForegroundColor) {
		setForegroundColor(newForegroundColor);
		return this;
	}

	/**
	 * Returns the foreground color of this entry in the GUI as HTML color text, or null.
	 *
	 * @return the foreground color of this entry in the GUI as HTML color text, or null
	 */
	public String getForegroundColor() {
		return foregroundColor;
	}

	/**
	 * Sets the background color of this entry in the GUI as HTML color text, or null.
	 *
	 * @param backgroundColor the background color of this entry in the GUI as HTML color text, or null
	 */
	public void setBackgroundColor(final String backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	/**
	 * Sets the background color of this entry in the GUI as HTML color text, or null and returns this object for method chaining.
	 *
	 * @param newBackgroundColor the background color of this entry in the GUI as HTML color text, or null
	 * @return this object
	 */
	public KdbxEntry withBackgroundColor(final String newBackgroundColor) {
		setBackgroundColor(newBackgroundColor);
		return this;
	}

	/**
	 * Returns the background color of this entry in the GUI as HTML color text, or null.
	 *
	 * @return the background color of this entry in the GUI as HTML color text, or null
	 */
	public String getBackgroundColor() {
		return backgroundColor;
	}

	/**
	 * Sets the URL override (command line) for opening the URL of this entry, or null.
	 *
	 * @param overrideURL the URL override (command line) for opening the URL of this entry, or null
	 */
	public void setOverrideURL(final String overrideURL) {
		this.overrideURL = overrideURL;
	}

	/**
	 * Sets the URL override (command line) for opening the URL of this entry, or null and returns this object for method chaining.
	 *
	 * @param newOverrideURL the URL override (command line) for opening the URL of this entry, or null
	 * @return this object
	 */
	public KdbxEntry withOverrideURL(final String newOverrideURL) {
		setOverrideURL(newOverrideURL);
		return this;
	}

	/**
	 * Returns the URL override (command line) for opening the URL of this entry, or null.
	 *
	 * @return the URL override (command line) for opening the URL of this entry, or null
	 */
	public String getOverrideURL() {
		return overrideURL;
	}

	/**
	 * Sets the tags of this entry, separated by "," or ";".
	 *
	 * @param tags the tags of this entry, separated by "," or ";"
	 */
	public void setTags(final String tags) {
		this.tags = tags;
	}

	/**
	 * Sets the tags of this entry, separated by "," or ";" and returns this object for method chaining.
	 *
	 * @param newTags the tags of this entry, separated by "," or ";"
	 * @return this object
	 */
	public KdbxEntry withTags(final String newTags) {
		setTags(newTags);
		return this;
	}

	/**
	 * Returns the tags of this entry, separated by "," or ";".
	 *
	 * @return the tags of this entry, separated by "," or ";"
	 */
	public String getTags() {
		return tags;
	}

	/**
	 * Sets the times and usage data of this entry.
	 *
	 * @param times the times and usage data of this entry
	 */
	public void setTimes(final KdbxTimes times) {
		if (times == null) {
			throw new IllegalArgumentException("Entry's times may not be null");
		} else {
			this.times = times;
		}
	}

	/**
	 * Sets the times and usage data of this entry and returns this object for method chaining.
	 *
	 * @param newTimes the times and usage data of this entry
	 * @return this object
	 */
	public KdbxEntry withTimes(final KdbxTimes newTimes) {
		setTimes(newTimes);
		return this;
	}

	/**
	 * Returns the times and usage data of this entry.
	 *
	 * @return the times and usage data of this entry
	 */
	public KdbxTimes getTimes() {
		return times;
	}

	/**
	 * Sets the value of an item.
	 *
	 * @param itemKey key of the item
	 * @param itemValue value of the item, which is written as its string representation
	 */
	public void setItem(final String itemKey, final Object itemValue) {
		items.put(itemKey, itemValue);
	}

	/**
	 * Sets the value of an item and returns this object for method chaining.
	 *
	 * @param newItemKey key of the item
	 * @param newItemValue value of the item, which is written as its string representation
	 * @return this object
	 */
	public KdbxEntry withItem(final String newItemKey, final Object newItemValue) {
		setItem(newItemKey, newItemValue);
		return this;
	}

	/**
	 * Returns the value of an item.
	 *
	 * @param itemKey key of the item
	 * @return the string representation of the value or null
	 */
	public String getItem(final String itemKey) {
		final Object itemValue = items.get(itemKey);
		return itemValue == null ? null : itemValue.toString();
	}

	/**
	 * Marks an item as protected or unprotected.
	 * Protected items are written encrypted with the inner stream cipher. Items read as protected are marked automatically, so they stay protected when written again.
	 * Standard items are also protected according to the memory protection settings of the database.
	 *
	 * @param itemKey key of the item
	 * @param isProtected true to protect the item
	 */
	public void setItemProtected(final String itemKey, final boolean isProtected) {
		if (isProtected) {
			protectedItemKeys.add(itemKey);
		} else {
			protectedItemKeys.remove(itemKey);
		}
	}

	/**
	 * Marks an item as protected or unprotected and returns this object for method chaining.
	 *
	 * @param itemKey key of the item
	 * @param isProtected true to protect the item
	 * @return this object
	 */
	public KdbxEntry withItemProtected(final String itemKey, final boolean isProtected) {
		setItemProtected(itemKey, isProtected);
		return this;
	}

	/**
	 * Returns whether an item is marked as protected.
	 *
	 * @param itemKey key of the item
	 * @return true if the item is marked as protected
	 */
	public boolean isItemProtected(final String itemKey) {
		return protectedItemKeys.contains(itemKey);
	}

	/**
	 * Returns the keys of items, which are marked as protected, as unmodifiable set.
	 *
	 * @return the keys of items, which are marked as protected, as unmodifiable set
	 */
	public Set<String> getProtectedItemKeys() {
		return Collections.unmodifiableSet(protectedItemKeys);
	}

	/**
	 * Sets the items (key/value strings) of this entry, including the standard items "Title", "UserName", "Password", "URL" and "Notes".
	 *
	 * @param items the items (key/value strings) of this entry, including the standard items "Title", "UserName", "Password", "URL" and "Notes"
	 */
	public void setItems(final Map<String, Object> items) {
		this.items = items;
	}

	/**
	 * Sets the items (key/value strings) of this entry, including the standard items "Title", "UserName", "Password", "URL" and "Notes" and returns this object for method chaining.
	 *
	 * @param newItems the items (key/value strings) of this entry, including the standard items "Title", "UserName", "Password", "URL" and "Notes"
	 * @return this object
	 */
	public KdbxEntry withItems(final Map<String, Object> newItems) {
		setItems(newItems);
		return this;
	}

	/**
	 * Returns the items (key/value strings) of this entry, including the standard items "Title", "UserName", "Password", "URL" and "Notes".
	 *
	 * @return the items (key/value strings) of this entry, including the standard items "Title", "UserName", "Password", "URL" and "Notes"
	 */
	public Map<String, Object> getItems() {
		return items;
	}

	/**
	 * Sets the auto-type settings of this entry.
	 *
	 * @param enabled whether auto-type is enabled
	 * @param dataTransferObfuscation data transfer obfuscation setting ("0" for none, "1" for two-channel auto-type obfuscation)
	 * @param defaultSequence default keystroke sequence or null
	 * @param associationWindow window title pattern of the auto-type association or null
	 * @param associationKeystrokeSequence keystroke sequence of the auto-type association or null
	 */
	public void setAutoType(final boolean enabled, final String dataTransferObfuscation, final String defaultSequence, final String associationWindow, final String associationKeystrokeSequence) {
		autoTypeEnabled = enabled;
		autoTypeDataTransferObfuscation = dataTransferObfuscation;
		autoTypeDefaultSequence = defaultSequence;
		autoTypeAssociationWindow = associationWindow;
		autoTypeAssociationKeystrokeSequence = associationKeystrokeSequence;
	}

	/**
	 * Sets the auto-type settings of this entry and returns this object for method chaining.
	 *
	 * @param newEnabled whether auto-type is enabled
	 * @param newDataTransferObfuscation data transfer obfuscation setting ("0" for none, "1" for two-channel auto-type obfuscation)
	 * @param newDefaultSequence default keystroke sequence or null
	 * @param newAssociationWindow window title pattern of the auto-type association or null
	 * @param newAssociationKeystrokeSequence keystroke sequence of the auto-type association or null
	 * @return this object
	 */
	public KdbxEntry withAutoType(final boolean newEnabled, final String newDataTransferObfuscation, final String newDefaultSequence, final String newAssociationWindow, final String newAssociationKeystrokeSequence) {
		setAutoType(newEnabled, newDataTransferObfuscation, newDefaultSequence, newAssociationWindow, newAssociationKeystrokeSequence);
		return this;
	}

	/**
	 * Returns whether auto-type is enabled for this entry.
	 *
	 * @return whether auto-type is enabled for this entry
	 */
	public boolean isAutoTypeEnabled() {
		return autoTypeEnabled;
	}

	/**
	 * Returns the auto-type data transfer obfuscation setting of this entry ("0" for none, "1" for two-channel auto-type obfuscation).
	 *
	 * @return the auto-type data transfer obfuscation setting of this entry ("0" for none, "1" for two-channel auto-type obfuscation)
	 */
	public String getAutoTypeDataTransferObfuscation() {
		return autoTypeDataTransferObfuscation;
	}

	/**
	 * Returns the default auto-type keystroke sequence of this entry, or null to use the sequence of the group.
	 *
	 * @return the default auto-type keystroke sequence of this entry, or null to use the sequence of the group
	 */
	public String getAutoTypeDefaultSequence() {
		return autoTypeDefaultSequence;
	}

	/**
	 * Returns the window title pattern of the auto-type association of this entry.
	 *
	 * @return the window title pattern of the auto-type association of this entry
	 */
	public String getAutoTypeAssociationWindow() {
		return autoTypeAssociationWindow;
	}

	/**
	 * Returns the keystroke sequence of the auto-type association of this entry.
	 *
	 * @return the keystroke sequence of the auto-type association of this entry
	 */
	public String getAutoTypeAssociationKeystrokeSequence() {
		return autoTypeAssociationKeystrokeSequence;
	}

	/**
	 * Sets the custom data items of this entry (KDBX 4.x).
	 *
	 * @param customData the custom data items of this entry (KDBX 4.x)
	 */
	public void setCustomData(final List<KdbxCustomDataItem> customData) {
		this.customData = customData;
	}

	/**
	 * Sets the custom data items of this entry (KDBX 4.x) and returns this object for method chaining.
	 *
	 * @param newCustomData the custom data items of this entry (KDBX 4.x)
	 * @return this object
	 */
	public KdbxEntry withCustomData(final List<KdbxCustomDataItem> newCustomData) {
		setCustomData(newCustomData);
		return this;
	}

	/**
	 * Returns the custom data items of this entry (KDBX 4.x).
	 *
	 * @return the custom data items of this entry (KDBX 4.x)
	 */
	public List<KdbxCustomDataItem> getCustomData() {
		return customData;
	}

	/**
	 * Returns the history entries (former versions) of this entry.
	 *
	 * @return the history entries (former versions) of this entry
	 */
	public List<KdbxEntry> getHistory() {
		return history;
	}

	/**
	 * Returns the attachments of this entry.
	 *
	 * @return the attachments of this entry
	 */
	public List<KdbxEntryBinary> getBinaries() {
		return binaries;
	}

	@Override
	public int hashCode() {
		return Objects.hash(autoTypeAssociationKeystrokeSequence, autoTypeAssociationWindow, autoTypeDataTransferObfuscation, autoTypeDefaultSequence, autoTypeEnabled,
				backgroundColor, binaries, customData, customIconUuid, foregroundColor, history, iconID, items, overrideURL, protectedItemKeys, tags, times, uuid);
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
			KdbxEntry other = (KdbxEntry) obj;
			return Objects.equals(autoTypeAssociationKeystrokeSequence, other.autoTypeAssociationKeystrokeSequence)
					&& Objects.equals(autoTypeAssociationWindow, other.autoTypeAssociationWindow)
					&& Objects.equals(autoTypeDataTransferObfuscation, other.autoTypeDataTransferObfuscation)
					&& Objects.equals(autoTypeDefaultSequence, other.autoTypeDefaultSequence)
					&& autoTypeEnabled == other.autoTypeEnabled
					&& Objects.equals(backgroundColor, other.backgroundColor)
					&& Objects.equals(binaries, other.binaries)
					&& Objects.equals(customData, other.customData)
					&& Objects.equals(customIconUuid, other.customIconUuid)
					&& Objects.equals(foregroundColor, other.foregroundColor)
					&& Objects.equals(history, other.history)
					&& Objects.equals(iconID, other.iconID)
					&& Objects.equals(items, other.items)
					&& Objects.equals(overrideURL, other.overrideURL)
					&& Objects.equals(protectedItemKeys, other.protectedItemKeys)
					&& Objects.equals(tags, other.tags)
					&& Objects.equals(times, other.times)
					&& Objects.equals(uuid, other.uuid);
		}
	}

	@Override
	public String toString() {
		return toString(false);
	}
	
	/**
	 * Returns a text representation of the main data of this entry.
	 *
	 * @param showPassword true to show the password in clear text, false to mask it
	 * @return the text representation
	 */
	public String toString(final boolean showPassword) {
		String returnString = "UUID: " + uuid + "\n";
		
		if (items.get("Title") != null) {
			returnString += "Title: " + items.get("Title") + "\n";
		}
		
		if (items.get("UserName") != null) {
			returnString += "Username: " + items.get("UserName") + "\n";
		}
		
		if (items.get("Password") != null) {
			if (showPassword) {
				returnString += "Password: " + items.get("Password") + "\n";
			} else {
				returnString += "Password: ***\n";
			}
		}
		
		if (items.get("URL") != null) {
			returnString += "URL: " + items.get("URL") + "\n";
		}
		
		if (items.get("Notes") != null) {
			returnString += "Notes: " + items.get("Notes") + "\n";
		}
		
		if (times.getCreationTime() != null) {
			returnString += "Created: " + times.getCreationTime() + "\n";
		}
		
		if (times.getLastModificationTime() != null) {
			returnString += "Changed: " + times.getLastModificationTime() + "\n";
		}
		
		for (Entry<String, Object> itemEntry : items.entrySet()) {
			if (!"Title".equals(itemEntry.getKey()) && !"UserName".equals(itemEntry.getKey()) && !"Password".equals(itemEntry.getKey())
					&& !"URL".equals(itemEntry.getKey()) && !"Notes".equals(itemEntry.getKey())) {
				returnString += itemEntry.getKey() + ": " + itemEntry.getValue() + "\n";
			}
		}
		
		if (iconID != null && iconID > 0) {
			returnString += "IconID: " + iconID + "\n";
		}
		
		if (customIconUuid != null) {
			returnString += "CustomIconUuid: " + customIconUuid + "\n";
		}
		
		if (foregroundColor != null) {
			returnString += "ForegroundColor: " + foregroundColor + "\n";
		}
		
		if (backgroundColor != null) {
			returnString += "BackgroundColor: " + backgroundColor + "\n";
		}
		
		if (overrideURL != null) {
			returnString += "OverrideURL: " + overrideURL + "\n";
		}
		
		if (tags != null) {
			returnString += "Tags: " + tags + "\n";
		}
		
		
		if (autoTypeEnabled) {
			returnString += "AutoTypeEnabled: " + autoTypeEnabled + "\n";
		}
		
		if (autoTypeDataTransferObfuscation != null) {
			returnString += "AutoTypeDataTransferObfuscation: " + autoTypeDataTransferObfuscation + "\n";
		}
		
		if (autoTypeDefaultSequence != null) {
			returnString += "AutoTypeDefaultSequence: " + autoTypeDefaultSequence + "\n";
		}
		
		if (autoTypeAssociationWindow != null) {
			returnString += "AutoTypeAssociationWindow: " + autoTypeAssociationWindow + "\n";
		}
		
		if (autoTypeAssociationKeystrokeSequence != null) {
			returnString += "AutoTypeAssociationKeystrokeSequence: " + autoTypeAssociationKeystrokeSequence + "\n";
		}
		
		if (customData != null && customData.size() > 0) {
			returnString += "CustomData size: " + customData.size() + "\n";
		}
		
		if (history != null && history.size() > 0) {
			returnString += "History size: " + history.size() + "\n";
		}
		
		if (binaries != null && binaries.size() > 0) {
			returnString += "Binaries size: " + binaries.size() + "\n";
		}
		
		return returnString;
	}
}
