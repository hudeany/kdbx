package de.soderer.utilities.kdbx.data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;

public class KdbxEntry {
	private KdbxUUID uuid;
	private Integer iconID;
	public KdbxUUID customIconUuid;
	private String foregroundColor;
	private String backgroundColor;
	private String overrideURL;
	private String tags;
	private KdbxTimes times = new KdbxTimes();
	private Map<String, Object> items = new LinkedHashMap<>();
	private boolean autoTypeEnabled = false;
	private String autoTypeDataTransferObfuscation;
	private String autoTypeDefaultSequence;
	private String autoTypeAssociationWindow;
	private String autoTypeAssociationKeystrokeSequence;
	private List<KdbxCustomDataItem> customData;
	private final List<KdbxEntry> history = new ArrayList<>();
	private final List<KdbxEntryBinary> binaries = new ArrayList<>();

	public void setUuid(final KdbxUUID uuid) {
		this.uuid = uuid;
	}

	public KdbxEntry withUuid(final KdbxUUID newUuid) {
		setUuid(newUuid);
		return this;
	}

	public KdbxUUID getUuid() {
		if (uuid == null) {
			uuid = new KdbxUUID();
		}
		return uuid;
	}

	public void setTitle(final String title) {
		items.put("Title", title);
	}

	public KdbxEntry withTitle(final String newTitle) {
		setTitle(newTitle);
		return this;
	}

	public String getTitle() {
		return (String) items.get("Title");
	}

	public void setUsername(final String username) {
		items.put("UserName", username);
	}

	public KdbxEntry withUsername(final String newUsername) {
		setUsername(newUsername);
		return this;
	}

	public String getUsername() {
		return (String) items.get("UserName");
	}

	public void setPassword(final String password) {
		items.put("Password", password);
	}

	public KdbxEntry withPassword(final String newPassword) {
		setPassword(newPassword);
		return this;
	}

	public String getPassword() {
		return (String) items.get("Password");
	}

	public void setUrl(final String url) {
		items.put("URL", url);
	}

	public KdbxEntry withUrl(final String newUrl) {
		setUrl(newUrl);
		return this;
	}

	public String getUrl() {
		return (String) items.get("URL");
	}

	public void setNotes(final String notes) {
		items.put("Notes", notes);
	}

	public KdbxEntry withNotes(final String newNotes) {
		setNotes(newNotes);
		return this;
	}

	public String getNotes() {
		return (String) items.get("Notes");
	}

	public void setIconID(final Integer iconID) {
		this.iconID = iconID;
	}

	public KdbxEntry withIconID(final Integer newIconID) {
		setIconID(newIconID);
		return this;
	}

	public Integer getIconID() {
		return iconID;
	}

	public void setCustomIconUuid(final KdbxUUID customIconUuid) {
		this.customIconUuid = customIconUuid;
	}

	public KdbxEntry withCustomIconUuid(final KdbxUUID newCustomIconUuid) {
		setCustomIconUuid(newCustomIconUuid);
		return this;
	}

	public KdbxUUID getCustomIconUuid() {
		return customIconUuid;
	}

	public void setForegroundColor(final String foregroundColor) {
		this.foregroundColor = foregroundColor;
	}

	public KdbxEntry withForegroundColor(final String newForegroundColor) {
		setForegroundColor(newForegroundColor);
		return this;
	}

	public String getForegroundColor() {
		return foregroundColor;
	}

	public void setBackgroundColor(final String backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	public KdbxEntry withBackgroundColor(final String newBackgroundColor) {
		setBackgroundColor(newBackgroundColor);
		return this;
	}

	public String getBackgroundColor() {
		return backgroundColor;
	}

	public void setOverrideURL(final String overrideURL) {
		this.overrideURL = overrideURL;
	}

	public KdbxEntry withOverrideURL(final String newOverrideURL) {
		setOverrideURL(newOverrideURL);
		return this;
	}

	public String getOverrideURL() {
		return overrideURL;
	}

	public void setTags(final String tags) {
		this.tags = tags;
	}

	public KdbxEntry withTags(final String newTags) {
		setTags(newTags);
		return this;
	}

	public String getTags() {
		return tags;
	}

	public void setTimes(final KdbxTimes times) {
		if (times == null) {
			throw new IllegalArgumentException("Entry's times may not be null");
		} else {
			this.times = times;
		}
	}

	public KdbxEntry withTimes(final KdbxTimes newTimes) {
		setTimes(newTimes);
		return this;
	}

	public KdbxTimes getTimes() {
		return times;
	}

	public void setItem(final String itemKey, final Object itemValue) {
		items.put(itemKey, itemValue);
	}

	public KdbxEntry withItem(final String newItemKey, final Object newItemValue) {
		setItem(newItemKey, newItemValue);
		return this;
	}

	public String getItem(final String itemKey) {
		return (String) items.get(itemKey);
	}

	public void setItems(final Map<String, Object> items) {
		this.items = items;
	}

	public KdbxEntry withItems(final Map<String, Object> newItems) {
		setItems(newItems);
		return this;
	}

	public Map<String, Object> getItems() {
		return items;
	}

	public void setAutoType(final boolean enabled, final String dataTransferObfuscation, final String defaultSequence, final String associationWindow, final String associationKeystrokeSequence) {
		autoTypeEnabled = enabled;
		autoTypeDataTransferObfuscation = dataTransferObfuscation;
		autoTypeDefaultSequence = defaultSequence;
		autoTypeAssociationWindow = associationWindow;
		autoTypeAssociationKeystrokeSequence = associationKeystrokeSequence;
	}

	public KdbxEntry withAutoType(final boolean newEnabled, final String newDataTransferObfuscation, final String newDefaultSequence, final String newAssociationWindow, final String newAssociationKeystrokeSequence) {
		setAutoType(newEnabled, newDataTransferObfuscation, newDefaultSequence, newAssociationWindow, newAssociationKeystrokeSequence);
		return this;
	}

	public boolean isAutoTypeEnabled() {
		return autoTypeEnabled;
	}

	public String getAutoTypeDataTransferObfuscation() {
		return autoTypeDataTransferObfuscation;
	}

	public String getAutoTypeDefaultSequence() {
		return autoTypeDefaultSequence;
	}

	public String getAutoTypeAssociationWindow() {
		return autoTypeAssociationWindow;
	}

	public String getAutoTypeAssociationKeystrokeSequence() {
		return autoTypeAssociationKeystrokeSequence;
	}

	/**
	 * Data items of stored files for this entry.
	 */
	public void setCustomData(final List<KdbxCustomDataItem> customData) {
		this.customData = customData;
	}

	public KdbxEntry withCustomData(final List<KdbxCustomDataItem> newCustomData) {
		setCustomData(newCustomData);
		return this;
	}

	/**
	 * Data items of stored files for this entry.
	 */
	public List<KdbxCustomDataItem> getCustomData() {
		return customData;
	}

	public List<KdbxEntry> getHistory() {
		return history;
	}

	public List<KdbxEntryBinary> getBinaries() {
		return binaries;
	}

	@Override
	public int hashCode() {
		return Objects.hash(autoTypeAssociationKeystrokeSequence, autoTypeAssociationWindow, autoTypeDataTransferObfuscation, autoTypeDefaultSequence, autoTypeEnabled,
				backgroundColor, binaries, customData, customIconUuid, foregroundColor, history, iconID, items, overrideURL, tags, times, uuid);
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
					&& Objects.equals(tags, other.tags)
					&& Objects.equals(times, other.times)
					&& Objects.equals(uuid, other.uuid);
		}
	}

	@Override
	public String toString() {
		return toString(false);
	}
	
	public String toString(boolean showPassword) {
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
