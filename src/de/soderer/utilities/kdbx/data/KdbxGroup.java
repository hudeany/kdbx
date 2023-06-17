package de.soderer.utilities.kdbx.data;

import java.util.ArrayList;
import java.util.List;

public class KdbxGroup {
	public String name;
	public KdbxUUID uuid;
	public KdbxTimes times;
	public String notes;
	public int iconID;
	public boolean isExpanded;
	public String defaultAutoTypeSequence;
	public String enableAutoType;
	public String enableSearching;
	public KdbxUUID lastTopVisibleEntry;
	public List<KdbxGroup> groups = new ArrayList<>();
	public List<KdbxEntry> entries = new ArrayList<>();

	public KdbxGroup setName(final String name) {
		this.name = name;
		return this;
	}

	public String getName() {
		return name;
	}

	public KdbxGroup setUuid(final KdbxUUID uuid) {
		this.uuid = uuid;
		return this;
	}

	public KdbxUUID getUuid() {
		return uuid;
	}

	public KdbxGroup setTimes(final KdbxTimes times) {
		this.times = times;
		return this;
	}

	public KdbxTimes getTimes() {
		return times;
	}

	public KdbxGroup setNotes(final String notes) {
		this.notes = notes;
		return this;
	}

	public String getNotes() {
		return notes;
	}

	public KdbxGroup setIconID(final int iconID) {
		this.iconID = iconID;
		return this;
	}

	public int getIconID() {
		return iconID;
	}

	public KdbxGroup setIsExpanded(final boolean isExpanded) {
		this.isExpanded = isExpanded;
		return this;
	}

	public boolean getIsExpanded() {
		return isExpanded;
	}

	public KdbxGroup setDefaultAutoTypeSequence(final String defaultAutoTypeSequence) {
		this.defaultAutoTypeSequence = defaultAutoTypeSequence;
		return this;
	}

	public String getDefaultAutoTypeSequence() {
		return defaultAutoTypeSequence;
	}

	public KdbxGroup setEnableAutoType(final String enableAutoType) {
		this.enableAutoType = enableAutoType;
		return this;
	}

	public String getEnableAutoType() {
		return enableAutoType;
	}

	public KdbxGroup setEnableSearching(final String enableSearching) {
		this.enableSearching = enableSearching;
		return this;
	}

	public String getEnableSearching() {
		return enableSearching;
	}

	public KdbxGroup setLastTopVisibleEntry(final KdbxUUID lastTopVisibleEntry) {
		this.lastTopVisibleEntry = lastTopVisibleEntry;
		return this;
	}

	public KdbxUUID getLastTopVisibleEntry() {
		return lastTopVisibleEntry;
	}

	public KdbxGroup setGroups(final List<KdbxGroup> groups) {
		this.groups = groups;
		return this;
	}

	public List<KdbxGroup> getGroups() {
		return groups;
	}

	public KdbxGroup setEntries(final List<KdbxEntry> entries) {
		this.entries = entries;
		return this;
	}

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
