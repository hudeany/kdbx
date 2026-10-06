package de.soderer.utilities.kdbx.data;

import java.util.ArrayList;
import java.util.List;

/**
 * Group of a KeePass database, which contains entries and subgroups.
 */
public class KdbxGroup {
	/**
	 * Name of this group.
	 */
	private String name;
	/**
	 * UUID of this group.
	 */
	private KdbxUUID uuid;
	/**
	 * Times and usage data of this group.
	 */
	private KdbxTimes times = new KdbxTimes();
	/**
	 * Notes of this group.
	 */
	private String notes;
	/**
	 * Id of the standard icon of this group (see {@link KdbxConstants.KdbxStandardIcon}), or null.
	 */
	private Integer iconID;
	/**
	 * UUID of the custom icon of this group (see {@link KdbxMeta#getCustomIcons()}), or null.
	 */
	private KdbxUUID customIconUuid;
	/**
	 * Whether this group is shown expanded in the GUI.
	 */
	private boolean expanded;
	/**
	 * Default auto-type keystroke sequence for entries of this group, or null to inherit it.
	 */
	private String defaultAutoTypeSequence;
	/**
	 * Auto-type setting: true, false or null for "inherit from parent group".
	 */
	private Boolean enableAutoType;
	/**
	 * Searching setting: true, false or null for "inherit from parent group".
	 */
	private Boolean enableSearching;
	/**
	 * UUID of the last entry at the top of the visible entry list of this group, or null.
	 */
	private KdbxUUID lastTopVisibleEntry;
	/**
	 * Custom data items of this group (KDBX 4.x).
	 */
	private List<KdbxCustomDataItem> customData;
	/**
	 * Subgroups of this group.
	 */
	private List<KdbxGroup> groups = new ArrayList<>();
	/**
	 * Entries of this group.
	 */
	private List<KdbxEntry> entries = new ArrayList<>();

	/**
	 * Creates an empty group. A random UUID is created on first access, if none is set.
	 */
	public KdbxGroup() {
		// nothing to do
	}

	/**
	 * Sets the name of this group.
	 *
	 * @param name the name of this group
	 */
	public void setName(final String name) {
		this.name = name;
	}

	/**
	 * Sets the name of this group and returns this object for method chaining.
	 *
	 * @param newName the name of this group
	 * @return this object
	 */
	public KdbxGroup withName(final String newName) {
		setName(newName);
		return this;
	}

	/**
	 * Returns the name of this group.
	 *
	 * @return the name of this group
	 */
	public String getName() {
		return name;
	}

	/**
	 * Sets the UUID of this group.
	 *
	 * @param uuid the UUID of this group
	 */
	public void setUuid(final KdbxUUID uuid) {
		this.uuid = uuid;
	}

	/**
	 * Sets the UUID of this group and returns this object for method chaining.
	 *
	 * @param newUuid the UUID of this group
	 * @return this object
	 */
	public KdbxGroup withUuid(final KdbxUUID newUuid) {
		setUuid(newUuid);
		return this;
	}

	/**
	 * Returns the UUID of this group. A random UUID is created, if none was set.
	 *
	 * @return the UUID of this group
	 */
	public KdbxUUID getUuid() {
		if (uuid == null) {
			uuid = new KdbxUUID();
		}
		return uuid;
	}

	/**
	 * Sets the times and usage data of this group.
	 *
	 * @param times the times and usage data of this group
	 */
	public void setTimes(final KdbxTimes times) {
		if (times == null) {
			throw new IllegalArgumentException("Group's times may not be null");
		} else {
			this.times = times;
		}
	}

	/**
	 * Sets the times and usage data of this group and returns this object for method chaining.
	 *
	 * @param newTimes the times and usage data of this group
	 * @return this object
	 */
	public KdbxGroup withTimes(final KdbxTimes newTimes) {
		setTimes(newTimes);
		return this;
	}

	/**
	 * Returns the times and usage data of this group.
	 *
	 * @return the times and usage data of this group
	 */
	public KdbxTimes getTimes() {
		return times;
	}

	/**
	 * Sets the notes of this group.
	 *
	 * @param notes the notes of this group
	 */
	public void setNotes(final String notes) {
		this.notes = notes;
	}

	/**
	 * Sets the notes of this group and returns this object for method chaining.
	 *
	 * @param newNotes the notes of this group
	 * @return this object
	 */
	public KdbxGroup withNotes(final String newNotes) {
		setNotes(newNotes);
		return this;
	}

	/**
	 * Returns the notes of this group.
	 *
	 * @return the notes of this group
	 */
	public String getNotes() {
		return notes;
	}

	/**
	 * Sets the id of the standard icon of this group (see {@link KdbxConstants.KdbxStandardIcon}), or null.
	 *
	 * @param iconID the id of the standard icon of this group (see {@link KdbxConstants.KdbxStandardIcon}), or null
	 */
	public void setIconID(final Integer iconID) {
		this.iconID = iconID;
	}

	/**
	 * Sets the id of the standard icon of this group (see {@link KdbxConstants.KdbxStandardIcon}), or null and returns this object for method chaining.
	 *
	 * @param newIconID the id of the standard icon of this group (see {@link KdbxConstants.KdbxStandardIcon}), or null
	 * @return this object
	 */
	public KdbxGroup withIconID(final Integer newIconID) {
		setIconID(newIconID);
		return this;
	}

	/**
	 * Returns the id of the standard icon of this group (see {@link KdbxConstants.KdbxStandardIcon}), or null.
	 *
	 * @return the id of the standard icon of this group (see {@link KdbxConstants.KdbxStandardIcon}), or null
	 */
	public Integer getIconID() {
		return iconID;
	}

	/**
	 * Sets the UUID of the custom icon of this group (see {@link KdbxMeta#getCustomIcons()}), or null.
	 *
	 * @param customIconUuid the UUID of the custom icon of this group (see {@link KdbxMeta#getCustomIcons()}), or null
	 */
	public void setCustomIconUuid(final KdbxUUID customIconUuid) {
		this.customIconUuid = customIconUuid;
	}

	/**
	 * Sets the UUID of the custom icon of this group (see {@link KdbxMeta#getCustomIcons()}), or null and returns this object for method chaining.
	 *
	 * @param newCustomIconUuid the UUID of the custom icon of this group (see {@link KdbxMeta#getCustomIcons()}), or null
	 * @return this object
	 */
	public KdbxGroup withCustomIconUuid(final KdbxUUID newCustomIconUuid) {
		setCustomIconUuid(newCustomIconUuid);
		return this;
	}

	/**
	 * Returns the UUID of the custom icon of this group (see {@link KdbxMeta#getCustomIcons()}), or null.
	 *
	 * @return the UUID of the custom icon of this group (see {@link KdbxMeta#getCustomIcons()}), or null
	 */
	public KdbxUUID getCustomIconUuid() {
		return customIconUuid;
	}

	/**
	 * Sets whether this group is shown expanded in the GUI.
	 *
	 * @param isExpanded whether this group is shown expanded in the GUI
	 */
	public void setExpanded(final boolean isExpanded) {
		expanded = isExpanded;
	}

	/**
	 * Sets whether this group is shown expanded in the GUI and returns this object for method chaining.
	 *
	 * @param newIsExpanded whether this group is shown expanded in the GUI
	 * @return this object
	 */
	public KdbxGroup withExpanded(final boolean newIsExpanded) {
		setExpanded(newIsExpanded);
		return this;
	}

	/**
	 * Returns whether this group is shown expanded in the GUI.
	 *
	 * @return whether this group is shown expanded in the GUI
	 */
	public boolean isExpanded() {
		return expanded;
	}

	/**
	 * Sets the default auto-type keystroke sequence for entries of this group, or null to inherit it.
	 *
	 * @param defaultAutoTypeSequence the default auto-type keystroke sequence for entries of this group, or null to inherit it
	 */
	public void setDefaultAutoTypeSequence(final String defaultAutoTypeSequence) {
		this.defaultAutoTypeSequence = defaultAutoTypeSequence;
	}

	/**
	 * Sets the default auto-type keystroke sequence for entries of this group, or null to inherit it and returns this object for method chaining.
	 *
	 * @param newDefaultAutoTypeSequence the default auto-type keystroke sequence for entries of this group, or null to inherit it
	 * @return this object
	 */
	public KdbxGroup withDefaultAutoTypeSequence(final String newDefaultAutoTypeSequence) {
		setDefaultAutoTypeSequence(newDefaultAutoTypeSequence);
		return this;
	}

	/**
	 * Returns the default auto-type keystroke sequence for entries of this group, or null to inherit it.
	 *
	 * @return the default auto-type keystroke sequence for entries of this group, or null to inherit it
	 */
	public String getDefaultAutoTypeSequence() {
		return defaultAutoTypeSequence;
	}

	/**
	 * Sets whether auto-type is enabled for this group.
	 *
	 * @param enableAutoType whether auto-type is enabled for this group
	 */
	public void setEnableAutoType(final boolean enableAutoType) {
		this.enableAutoType = enableAutoType;
	}

	/**
	 * Sets the auto-type setting of this group: true, false or null for "inherit from parent group".
	 *
	 * @param enableAutoTypeSetting the auto-type setting of this group: true, false or null for "inherit from parent group"
	 */
	public void setEnableAutoTypeSetting(final Boolean enableAutoTypeSetting) {
		enableAutoType = enableAutoTypeSetting;
	}

	/**
	 * Sets the auto-type setting of this group: true, false or null for "inherit from parent group" and returns this object for method chaining.
	 *
	 * @param newEnableAutoTypeSetting the auto-type setting of this group: true, false or null for "inherit from parent group"
	 * @return this object
	 */
	public KdbxGroup withEnableAutoTypeSetting(final Boolean newEnableAutoTypeSetting) {
		setEnableAutoTypeSetting(newEnableAutoTypeSetting);
		return this;
	}

	/**
	 * Returns the auto-type setting of this group: true, false or null for "inherit from parent group".
	 *
	 * @return the auto-type setting of this group: true, false or null for "inherit from parent group"
	 */
	public Boolean getEnableAutoTypeSetting() {
		return enableAutoType;
	}

	/**
	 * Sets whether auto-type is enabled for this group and returns this object for method chaining.
	 *
	 * @param newEnableAutoType whether auto-type is enabled for this group
	 * @return this object
	 */
	public KdbxGroup withEnableAutoType(final boolean newEnableAutoType) {
		setEnableAutoType(newEnableAutoType);
		return this;
	}

	/**
	 * Returns whether auto-type is enabled for this group. The setting "inherit from parent group" (null) is reported as enabled.
	 *
	 * @return whether auto-type is enabled for this group
	 */
	public boolean isEnableAutoType() {
		return !Boolean.FALSE.equals(enableAutoType);
	}

	/**
	 * Sets whether searching is enabled for this group.
	 *
	 * @param enableSearching whether searching is enabled for this group
	 */
	public void setEnableSearching(final boolean enableSearching) {
		this.enableSearching = enableSearching;
	}

	/**
	 * Sets the searching setting of this group: true, false or null for "inherit from parent group".
	 *
	 * @param enableSearchingSetting the searching setting of this group: true, false or null for "inherit from parent group"
	 */
	public void setEnableSearchingSetting(final Boolean enableSearchingSetting) {
		enableSearching = enableSearchingSetting;
	}

	/**
	 * Sets the searching setting of this group: true, false or null for "inherit from parent group" and returns this object for method chaining.
	 *
	 * @param newEnableSearchingSetting the searching setting of this group: true, false or null for "inherit from parent group"
	 * @return this object
	 */
	public KdbxGroup withEnableSearchingSetting(final Boolean newEnableSearchingSetting) {
		setEnableSearchingSetting(newEnableSearchingSetting);
		return this;
	}

	/**
	 * Returns the searching setting of this group: true, false or null for "inherit from parent group".
	 *
	 * @return the searching setting of this group: true, false or null for "inherit from parent group"
	 */
	public Boolean getEnableSearchingSetting() {
		return enableSearching;
	}

	/**
	 * Sets whether searching is enabled for this group and returns this object for method chaining.
	 *
	 * @param newEnableSearching whether searching is enabled for this group
	 * @return this object
	 */
	public KdbxGroup withEnableSearching(final boolean newEnableSearching) {
		setEnableSearching(newEnableSearching);
		return this;
	}

	/**
	 * Returns whether searching is enabled for this group. The setting "inherit from parent group" (null) is reported as enabled.
	 *
	 * @return whether searching is enabled for this group
	 */
	public boolean isEnableSearching() {
		return !Boolean.FALSE.equals(enableSearching);
	}

	/**
	 * Sets the UUID of the last entry at the top of the visible entry list of this group, or null.
	 *
	 * @param lastTopVisibleEntry the UUID of the last entry at the top of the visible entry list of this group, or null
	 */
	public void setLastTopVisibleEntry(final KdbxUUID lastTopVisibleEntry) {
		this.lastTopVisibleEntry = lastTopVisibleEntry;
	}

	/**
	 * Sets the UUID of the last entry at the top of the visible entry list of this group, or null and returns this object for method chaining.
	 *
	 * @param newLastTopVisibleEntry the UUID of the last entry at the top of the visible entry list of this group, or null
	 * @return this object
	 */
	public KdbxGroup withLastTopVisibleEntry(final KdbxUUID newLastTopVisibleEntry) {
		setLastTopVisibleEntry(newLastTopVisibleEntry);
		return this;
	}

	/**
	 * Returns the UUID of the last entry at the top of the visible entry list of this group, or null.
	 *
	 * @return the UUID of the last entry at the top of the visible entry list of this group, or null
	 */
	public KdbxUUID getLastTopVisibleEntry() {
		return lastTopVisibleEntry;
	}

	/**
	 * Sets the custom data items of this group (KDBX 4.x).
	 *
	 * @param customData the custom data items of this group (KDBX 4.x)
	 */
	public void setCustomData(final List<KdbxCustomDataItem> customData) {
		this.customData = customData;
	}

	/**
	 * Sets the custom data items of this group (KDBX 4.x) and returns this object for method chaining.
	 *
	 * @param newCustomData the custom data items of this group (KDBX 4.x)
	 * @return this object
	 */
	public KdbxGroup withCustomData(final List<KdbxCustomDataItem> newCustomData) {
		setCustomData(newCustomData);
		return this;
	}

	/**
	 * Returns the custom data items of this group (KDBX 4.x).
	 *
	 * @return the custom data items of this group (KDBX 4.x)
	 */
	public List<KdbxCustomDataItem> getCustomData() {
		return customData;
	}

	/**
	 * Sets the subgroups of this group.
	 *
	 * @param groups the subgroups of this group
	 */
	public void setGroups(final List<KdbxGroup> groups) {
		this.groups = groups;
	}

	/**
	 * Sets the subgroups of this group and returns this object for method chaining.
	 *
	 * @param newGroups the subgroups of this group
	 * @return this object
	 */
	public KdbxGroup withGroups(final List<KdbxGroup> newGroups) {
		setGroups(newGroups);
		return this;
	}

	/**
	 * Returns the subgroups of this group.
	 *
	 * @return the subgroups of this group
	 */
	public List<KdbxGroup> getGroups() {
		return groups;
	}

	/**
	 * Sets the entries of this group.
	 *
	 * @param entries the entries of this group
	 */
	public void setEntries(final List<KdbxEntry> entries) {
		this.entries = entries;
	}

	/**
	 * Sets the entries of this group and returns this object for method chaining.
	 *
	 * @param newEntries the entries of this group
	 * @return this object
	 */
	public KdbxGroup withEntries(final List<KdbxEntry> newEntries) {
		setEntries(newEntries);
		return this;
	}

	/**
	 * Returns the entries of this group.
	 *
	 * @return the entries of this group
	 */
	public List<KdbxEntry> getEntries() {
		return entries;
	}

	/**
	 * Searches a group by its UUID in the subgroups of this group including nested subgroups.
	 *
	 * @param groupUuid UUID of the group
	 * @return the group or null if not found
	 */
	public KdbxGroup getGroupByUUID(final KdbxUUID groupUuid) {
		for (final KdbxGroup group : groups) {
			if (group.getUuid().equals(groupUuid)) {
				return group;
			} else {
				final KdbxGroup subGroup = group.getGroupByUUID(groupUuid);
				if (subGroup != null) {
					return subGroup;
				}
			}
		}
		return null;
	}

	/**
	 * Searches an entry by its UUID in this group and all nested subgroups. History entries are not searched.
	 *
	 * @param entryUuid UUID of the entry
	 * @return the entry or null if not found
	 */
	public KdbxEntry getEntryByUUID(final KdbxUUID entryUuid) {
		for (final KdbxEntry entry : entries) {
			if (entry.getUuid().equals(entryUuid)) {
				return entry;
			}
		}
		for (final KdbxGroup group : groups) {
			final KdbxEntry entry = group.getEntryByUUID(entryUuid);
			if (entry != null) {
				return entry;
			}
		}
		return null;
	}

	/**
	 * Returns the path to a group or entry as list of UUIDs: from this group down to the searched object itself.
	 *
	 * @param uuidToSearch UUID of the searched group or entry
	 * @return the UUID path or null if not found within this group
	 */
	public List<KdbxUUID> getUuidPath(final KdbxUUID uuidToSearch) {
		if (getUuid().equals(uuidToSearch)) {
			final List<KdbxUUID> pathUuids = new ArrayList<>();
			pathUuids.add(getUuid());
			return pathUuids;
		}
		for (final KdbxEntry entry : entries) {
			if (entry.getUuid().equals(uuidToSearch)) {
				final List<KdbxUUID> pathUuids = new ArrayList<>();
				pathUuids.add(getUuid());
				pathUuids.add(entry.getUuid());
				return pathUuids;
			}
		}
		for (final KdbxGroup group : groups) {
			final List<KdbxUUID> subPathUuids = group.getUuidPath(uuidToSearch);
			if (subPathUuids != null) {
				subPathUuids.add(0, getUuid());
				return subPathUuids;
			}
		}
		return null;
	}

	/**
	 * Returns all subgroups of this group including nested subgroups (without this group itself).
	 *
	 * @return new list of all subgroups
	 */
	public List<KdbxGroup> getAllGroups() {
		final List<KdbxGroup> groupsList = new ArrayList<>();
		for (final KdbxGroup group : groups) {
			groupsList.add(group);
		}
		for (final KdbxGroup group : groups) {
			groupsList.addAll(group.getAllGroups());
		}
		return groupsList;
	}

	/**
	 * Returns all entries of this group and all nested subgroups. History entries are not included.
	 *
	 * @return new list of all entries
	 */
	public List<KdbxEntry> getAllEntries() {
		final List<KdbxEntry> entriesList = new ArrayList<>();
		for (final KdbxEntry entry : entries) {
			entriesList.add(entry);
		}
		for (final KdbxGroup group : groups) {
			entriesList.addAll(group.getAllEntries());
		}
		return entriesList;
	}
}
