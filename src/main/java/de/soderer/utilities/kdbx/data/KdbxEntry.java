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

	public KdbxEntry setUuid(final KdbxUUID uuid) {
		this.uuid = uuid;
		return this;
	}

	public KdbxUUID getUuid() {
		if (uuid == null) {
			uuid = new KdbxUUID();
		}
		return uuid;
	}

	public KdbxEntry setTitle(final String title) {
		items.put("Title", title);
		return this;
	}

	public String getTitle() {
		return (String) items.get("Title");
	}

	public KdbxEntry setUsername(final String username) {
		items.put("UserName", username);
		return this;
	}

	public String getUsername() {
		return (String) items.get("UserName");
	}

	public KdbxEntry setPassword(final String password) {
		items.put("Password", password);
		return this;
	}

	public String getPassword() {
		return (String) items.get("Password");
	}

	public KdbxEntry setUrl(final String url) {
		items.put("URL", url);
		return this;
	}

	public String getUrl() {
		return (String) items.get("URL");
	}

	public KdbxEntry setNotes(final String notes) {
		items.put("Notes", notes);
		return this;
	}

	public String getNotes() {
		return (String) items.get("Notes");
	}

	public KdbxEntry setIconID(final Integer iconID) {
		this.iconID = iconID;
		return this;
	}

	public Integer getIconID() {
		return iconID;
	}

	public KdbxEntry setCustomIconUuid(final KdbxUUID customIconUuid) {
		this.customIconUuid = customIconUuid;
		return this;
	}

	public KdbxUUID getCustomIconUuid() {
		return customIconUuid;
	}

	public KdbxEntry setForegroundColor(final String foregroundColor) {
		this.foregroundColor = foregroundColor;
		return this;
	}

	public String getForegroundColor() {
		return foregroundColor;
	}

	public KdbxEntry setBackgroundColor(final String backgroundColor) {
		this.backgroundColor = backgroundColor;
		return this;
	}

	public String getBackgroundColor() {
		return backgroundColor;
	}

	public KdbxEntry setOverrideURL(final String overrideURL) {
		this.overrideURL = overrideURL;
		return this;
	}

	public String getOverrideURL() {
		return overrideURL;
	}

	public KdbxEntry setTags(final String tags) {
		this.tags = tags;
		return this;
	}

	public String getTags() {
		return tags;
	}

	public KdbxEntry setTimes(final KdbxTimes times) {
		if (times == null) {
			throw new IllegalArgumentException("Entry's times may not be null");
		} else {
			this.times = times;
			return this;
		}
	}

	public KdbxTimes getTimes() {
		return times;
	}

	public KdbxEntry setItem(final String itemKey, final Object itemValue) {
		items.put(itemKey, itemValue);
		return this;
	}

	public String getItem(final String itemKey) {
		return (String) items.get(itemKey);
	}

	public KdbxEntry setItems(final Map<String, Object> items) {
		this.items = items;
		return this;
	}

	public Map<String, Object> getItems() {
		return items;
	}

	public KdbxEntry setAutoType(final boolean enabled, final String dataTransferObfuscation, final String defaultSequence, final String associationWindow, final String associationKeystrokeSequence) {
		autoTypeEnabled = enabled;
		autoTypeDataTransferObfuscation = dataTransferObfuscation;
		autoTypeDefaultSequence = defaultSequence;
		autoTypeAssociationWindow = associationWindow;
		autoTypeAssociationKeystrokeSequence = associationKeystrokeSequence;
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
	public KdbxEntry setCustomData(final List<KdbxCustomDataItem> customData) {
		this.customData = customData;
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
