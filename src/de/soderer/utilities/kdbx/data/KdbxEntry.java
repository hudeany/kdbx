package de.soderer.utilities.kdbx.data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class KdbxEntry {
	private KdbxUUID uuid;
	private int iconID;
	private String foregroundColor;
	private String backgroundColor;
	private String overrideURL;
	private String tags;
	private KdbxTimes times;
	private Map<String, Object> items = new LinkedHashMap<>();
	private boolean autoTypeEnabled = false;
	private String autoTypeDataTransferObfuscation;
	private String autoTypeAssociationWindow;
	private String autoTypeAssociationKeystrokeSequence;
	private final List<KdbxEntry> history = new ArrayList<>();

	public KdbxEntry setUuid(final KdbxUUID uuid) {
		this.uuid = uuid;
		return this;
	}

	public KdbxUUID getUuid() {
		return uuid;
	}

	public KdbxEntry setTitle(final KdbxTimes title) {
		items.put("Title", title);
		return this;
	}

	public String getTitle() {
		return (String) items.get("Title");
	}

	public KdbxEntry setUsername(final KdbxTimes username) {
		items.put("Username", username);
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
		items.put("Url", url);
		return this;
	}

	public String getUrl() {
		return (String) items.get("Url");
	}

	public KdbxEntry setNotes(final String notes) {
		items.put("Notes", notes);
		return this;
	}

	public String getNotes() {
		return (String) items.get("Notes");
	}

	public int getIconID() {
		return iconID;
	}

	public void setIconID(final int iconID) {
		this.iconID = iconID;
	}

	public String getForegroundColor() {
		return foregroundColor;
	}

	public void setForegroundColor(final String foregroundColor) {
		this.foregroundColor = foregroundColor;
	}

	public String getBackgroundColor() {
		return backgroundColor;
	}

	public void setBackgroundColor(final String backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	public String getOverrideURL() {
		return overrideURL;
	}

	public void setOverrideURL(final String overrideURL) {
		this.overrideURL = overrideURL;
	}

	public String getTags() {
		return tags;
	}

	public void setTags(final String tags) {
		this.tags = tags;
	}

	public KdbxEntry setTimes(final KdbxTimes times) {
		this.times = times;
		return this;
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

	public Map<String, Object> getItems() {
		return items;
	}

	public void setItems(final Map<String, Object> items) {
		this.items = items;
	}

	public void setAutoType(final boolean enabled, final String dataTransferObfuscation, final String associationWindow, final String associationKeystrokeSequence) {
		autoTypeEnabled = enabled;
		autoTypeDataTransferObfuscation = dataTransferObfuscation;
		autoTypeAssociationWindow = associationWindow;
		autoTypeAssociationKeystrokeSequence = associationKeystrokeSequence;
	}

	public boolean getAutoTypeEnabled() {
		return autoTypeEnabled;
	}

	public String getAutoTypeDataTransferObfuscation() {
		return autoTypeDataTransferObfuscation;
	}

	public String getAutoTypeAssociationWindow() {
		return autoTypeAssociationWindow;
	}

	public String getAutoTypeAssociationKeystrokeSequence() {
		return autoTypeAssociationKeystrokeSequence;
	}

	public List<KdbxEntry> getHistory() {
		return history;
	}
}
