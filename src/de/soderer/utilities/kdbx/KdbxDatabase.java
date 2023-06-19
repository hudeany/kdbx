package de.soderer.utilities.kdbx;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxUUID;

public class KdbxDatabase {
	public KdbxMeta meta = new KdbxMeta();
	public List<KdbxGroup> groups = new ArrayList<>();
	public List<KdbxEntry> entries = new ArrayList<>();
	public Map<KdbxUUID, ZonedDateTime> deletedObjects = new LinkedHashMap<>();

	public KdbxDatabase setMeta(final KdbxMeta kdbxMeta) {
		meta = kdbxMeta;
		return this;
	}

	public KdbxMeta getMeta() {
		return meta;
	}

	public KdbxDatabase setGroups(final List<KdbxGroup> groups) {
		this.groups = groups;
		return this;
	}

	public List<KdbxGroup> getGroups() {
		return groups;
	}

	public KdbxDatabase setEntries(final List<KdbxEntry> entries) {
		this.entries = entries;
		return this;
	}

	public List<KdbxEntry> getEntries() {
		return entries;
	}

	public Map<KdbxUUID, ZonedDateTime> getDeletedObjects() {
		return deletedObjects;
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

	public List<KdbxUUID> getUuidPath(final KdbxUUID uuid) {
		for (final KdbxEntry entry : entries) {
			if (entry.getUuid().equals(uuid)) {
				final List<KdbxUUID> pathUuids = new ArrayList<>();
				pathUuids.add(entry.getUuid());
				return pathUuids;
			}
		}
		for (final KdbxGroup group : groups) {
			if (group.getUuid().equals(uuid)) {
				final List<KdbxUUID> pathUuids = new ArrayList<>();
				pathUuids.add(group.getUuid());
				return pathUuids;
			} else {
				final List<KdbxUUID> subPathUuids = group.getUuidPath(uuid);
				if (subPathUuids != null) {
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
