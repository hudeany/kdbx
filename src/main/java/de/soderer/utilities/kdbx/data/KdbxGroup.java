package de.soderer.utilities.kdbx.data;

import java.util.ArrayList;
import java.util.List;

public class KdbxGroup {
	public String name;
	public KdbxUUID uuid;
	private KdbxTimes times = new KdbxTimes();
	public String notes;
	public Integer iconID;
	public KdbxUUID customIconUuid;
	public boolean expanded;
	public String defaultAutoTypeSequence;
	public boolean enableAutoType;
	public boolean enableSearching;
	public KdbxUUID lastTopVisibleEntry;
	private List<KdbxCustomDataItem> customData;
	public List<KdbxGroup> groups = new ArrayList<>();
	public List<KdbxEntry> entries = new ArrayList<>();

	/**
	 * Name of this group
	 */
	public void setName(final String name) {
		this.name = name;
	}

	public KdbxGroup withName(final String newName) {
		setName(newName);
		return this;
	}

	/**
	 * Name of this group
	 */
	public String getName() {
		return name;
	}

	public void setUuid(final KdbxUUID uuid) {
		this.uuid = uuid;
	}

	public KdbxGroup withUuid(final KdbxUUID newUuid) {
		setUuid(newUuid);
		return this;
	}

	public KdbxUUID getUuid() {
		if (uuid == null) {
			uuid = new KdbxUUID();
		}
		return uuid;
	}

	/**
	 * KDBX times of this group
	 */
	public void setTimes(final KdbxTimes times) {
		if (times == null) {
			throw new IllegalArgumentException("Group's times may not be null");
		} else {
			this.times = times;
		}
	}

	public KdbxGroup withTimes(final KdbxTimes newTimes) {
		setTimes(newTimes);
		return this;
	}

	/**
	 * KDBX times of this group
	 */
	public KdbxTimes getTimes() {
		return times;
	}

	/**
	 * Notes for this group
	 */
	public void setNotes(final String notes) {
		this.notes = notes;
	}

	public KdbxGroup withNotes(final String newNotes) {
		setNotes(newNotes);
		return this;
	}

	/**
	 * Notes for this group
	 */
	public String getNotes() {
		return notes;
	}

	/**
	 * Standard icon id for this group
	 */
	public void setIconID(final Integer iconID) {
		this.iconID = iconID;
	}

	public KdbxGroup withIconID(final Integer newIconID) {
		setIconID(newIconID);
		return this;
	}

	/**
	 * Standard icon id for this group
	 */
	public Integer getIconID() {
		return iconID;
	}

	/**
	 * Custom icon uuid for this group, which is stored in meta data of its database
	 */
	public void setCustomIconUuid(final KdbxUUID customIconUuid) {
		this.customIconUuid = customIconUuid;
	}

	public KdbxGroup withCustomIconUuid(final KdbxUUID newCustomIconUuid) {
		setCustomIconUuid(newCustomIconUuid);
		return this;
	}

	/**
	 * Custom icon uuid for this group, which is stored in meta data of its database
	 */
	public KdbxUUID getCustomIconUuid() {
		return customIconUuid;
	}

	/**
	 * This group is shown in expanded state in a GUI
	 */
	public void setExpanded(final boolean isExpanded) {
		expanded = isExpanded;
	}

	public KdbxGroup withExpanded(final boolean newIsExpanded) {
		setExpanded(newIsExpanded);
		return this;
	}

	/**
	 * This group is shown in expanded state in a GUI
	 */
	public boolean isExpanded() {
		return expanded;
	}

	/**
	 * Default auto type sequence for this group
	 */
	public void setDefaultAutoTypeSequence(final String defaultAutoTypeSequence) {
		this.defaultAutoTypeSequence = defaultAutoTypeSequence;
	}

	public KdbxGroup withDefaultAutoTypeSequence(final String newDefaultAutoTypeSequence) {
		setDefaultAutoTypeSequence(newDefaultAutoTypeSequence);
		return this;
	}

	/**
	 * Default auto type sequence for this group
	 */
	public String getDefaultAutoTypeSequence() {
		return defaultAutoTypeSequence;
	}

	/**
	 * Auto type is enabled for this group
	 */
	public void setEnableAutoType(final boolean enableAutoType) {
		this.enableAutoType = enableAutoType;
	}

	public KdbxGroup withEnableAutoType(final boolean newEnableAutoType) {
		setEnableAutoType(newEnableAutoType);
		return this;
	}

	/**
	 * Auto type is enabled for this group
	 */
	public boolean isEnableAutoType() {
		return enableAutoType;
	}

	/**
	 * Include this group is search operations
	 */
	public void setEnableSearching(final boolean enableSearching) {
		this.enableSearching = enableSearching;
	}

	public KdbxGroup withEnableSearching(final boolean newEnableSearching) {
		setEnableSearching(newEnableSearching);
		return this;
	}

	/**
	 * Include this group is search operations
	 */
	public boolean isEnableSearching() {
		return enableSearching;
	}

	/**
	 * UUID of the last scroll visible entry
	 */
	public void setLastTopVisibleEntry(final KdbxUUID lastTopVisibleEntry) {
		this.lastTopVisibleEntry = lastTopVisibleEntry;
	}

	public KdbxGroup withLastTopVisibleEntry(final KdbxUUID newLastTopVisibleEntry) {
		setLastTopVisibleEntry(newLastTopVisibleEntry);
		return this;
	}

	/**
	 * UUID of the last scroll visible entry
	 */
	public KdbxUUID getLastTopVisibleEntry() {
		return lastTopVisibleEntry;
	}

	/**
	 * Binary data items of stored files for this group.
	 * MAY ONLY be present in KDBX 4.0 or higher.
	 */
	public void setCustomData(final List<KdbxCustomDataItem> customData) {
		this.customData = customData;
	}

	public KdbxGroup withCustomData(final List<KdbxCustomDataItem> newCustomData) {
		setCustomData(newCustomData);
		return this;
	}

	/**
	 * Binary data items of stored files for this group.
	 * MAY ONLY be present in KDBX 4.0 or higher.
	 */
	public List<KdbxCustomDataItem> getCustomData() {
		return customData;
	}

	/**
	 * Sub groups of this group
	 */
	public void setGroups(final List<KdbxGroup> groups) {
		this.groups = groups;
	}

	public KdbxGroup withGroups(final List<KdbxGroup> newGroups) {
		setGroups(newGroups);
		return this;
	}

	/**
	 * Sub groups of this group
	 */
	public List<KdbxGroup> getGroups() {
		return groups;
	}

	/**
	 * Entries of this group
	 */
	public void setEntries(final List<KdbxEntry> entries) {
		this.entries = entries;
	}

	public KdbxGroup withEntries(final List<KdbxEntry> newEntries) {
		setEntries(newEntries);
		return this;
	}

	/**
	 * Entries of this group
	 */
	public List<KdbxEntry> getEntries() {
		return entries;
	}

	public KdbxGroup getGroupByUUID(final KdbxUUID groupUuid) {
		for (final KdbxGroup group : groups) {
			if (group.getUuid().equals(groupUuid)) {
				return group;
			}
		}
		return null;
	}

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

	public List<KdbxUUID> getUuidPath(final KdbxUUID uuidToSearch) {
		for (final KdbxEntry entry : entries) {
			if (entry.getUuid().equals(uuidToSearch)) {
				final List<KdbxUUID> pathUuids = new ArrayList<>();
				pathUuids.add(entry.getUuid());
				return pathUuids;
			}
		}
		for (final KdbxGroup group : groups) {
			if (group.getUuid().equals(uuidToSearch)) {
				final List<KdbxUUID> pathUuids = new ArrayList<>();
				pathUuids.add(group.getUuid());
				return pathUuids;
			} else {
				final List<KdbxUUID> subPathUuids = group.getUuidPath(uuidToSearch);
				if (subPathUuids != null) {
					subPathUuids.add(0, getUuid());
					return subPathUuids;
				}
			}
		}
		return null;
	}

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
