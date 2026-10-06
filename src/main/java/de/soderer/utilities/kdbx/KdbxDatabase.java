package de.soderer.utilities.kdbx;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.soderer.utilities.kdbx.data.KdbxBinary;
import de.soderer.utilities.kdbx.data.KdbxConstants;
import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxEntryBinary;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * Data of a KeePass database: meta data, groups, entries, deleted objects and binary attachments.
 * <p>
 * Entries and groups may be stored directly in the database (root level) or in groups.
 */
public class KdbxDatabase {
	/**
	 * Creates an empty database with default meta data.
	 */
	public KdbxDatabase() {
		// nothing to do
	}

	/**
	 * Header format of the file, from which the database was read.
	 */
	private KdbxHeaderFormat headerFormat;
	/**
	 * Binary data of entry attachments as stored in the file.
	 */
	private List<KdbxBinary> binaryAttachments = null;
	/**
	 * Meta data of the database.
	 */
	private KdbxMeta meta = new KdbxMeta();
	/**
	 * Top level groups of the database.
	 */
	private List<KdbxGroup> groups = new ArrayList<>();
	/**
	 * Entries on root level of the database, which are not contained in a group.
	 */
	private List<KdbxEntry> entries = new ArrayList<>();
	/**
	 * Deletion times of deleted groups and entries by UUID.
	 */
	private final Map<KdbxUUID, ZonedDateTime> deletedObjects = new LinkedHashMap<>();
	/**
	 * Random salt of the credentials fingerprint.
	 */
	private byte[] credentialsFingerprintSalt = null;
	/**
	 * Salted HMAC of the composite key hash used for the last read or write, to detect changed credentials. The composite key hash itself is not kept.
	 */
	private byte[] credentialsFingerprint = null;

	/**
	 * Sets the header format of the file, from which the database was read.
	 *
	 * @param headerFormat the header format of the file, from which the database was read
	 */
	public void setHeaderFormat(final KdbxHeaderFormat headerFormat) {
		this.headerFormat = headerFormat;
	}

	/**
	 * Sets the header format of the file, from which the database was read and returns this object for method chaining.
	 *
	 * @param newHeaderFormat the header format of the file, from which the database was read
	 * @return this object
	 */
	public KdbxDatabase withHeaderFormat(final KdbxHeaderFormat newHeaderFormat) {
		setHeaderFormat(newHeaderFormat);
		return this;
	}

	/**
	 * Returns the header format of the file, from which the database was read.
	 *
	 * @return the header format of the file, from which the database was read
	 */
	public KdbxHeaderFormat getHeaderFormat() {
		return headerFormat;
	}

	/**
	 * Sets the binary data of entry attachments: in data format version 3.1 and lower stored in the meta data binaries, in version 4.0 and higher in the inner header. Rebuilt by {@link #validate()} before writing.
	 *
	 * @param binaryAttachments the binary data of entry attachments: in data format version 3.1 and lower stored in the meta data binaries, in version 4.0 and higher in the inner header. Rebuilt by {@link #validate()} before writing
	 */
	public void setBinaryAttachments(final List<KdbxBinary> binaryAttachments) {
		this.binaryAttachments = binaryAttachments;
	}

	/**
	 * Sets the binary data of entry attachments: in data format version 3.1 and lower stored in the meta data binaries, in version 4.0 and higher in the inner header. Rebuilt by {@link #validate()} before writing and returns this object for method chaining.
	 *
	 * @param newBinaryAttachments the binary data of entry attachments: in data format version 3.1 and lower stored in the meta data binaries, in version 4.0 and higher in the inner header. Rebuilt by {@link #validate()} before writing
	 * @return this object
	 */
	public KdbxDatabase withBinaryAttachments(final List<KdbxBinary> newBinaryAttachments) {
		setBinaryAttachments(newBinaryAttachments);
		return this;
	}

	/**
	 * Returns the binary data of entry attachments: in data format version 3.1 and lower stored in the meta data binaries, in version 4.0 and higher in the inner header. Rebuilt by {@link #validate()} before writing.
	 *
	 * @return the binary data of entry attachments: in data format version 3.1 and lower stored in the meta data binaries, in version 4.0 and higher in the inner header. Rebuilt by {@link #validate()} before writing
	 */
	public List<KdbxBinary> getBinaryAttachments() {
		return binaryAttachments;
	}

	/**
	 * Sets the meta data of the database.
	 *
	 * @param meta the meta data of the database
	 */
	public void setMeta(final KdbxMeta meta) {
		if (meta == null) {
			throw new IllegalArgumentException("Database's meta may not be null");
		} else {
			this.meta = meta;
		}
	}

	/**
	 * Sets the meta data of the database and returns this object for method chaining.
	 *
	 * @param newMeta the meta data of the database
	 * @return this object
	 */
	public KdbxDatabase withMeta(final KdbxMeta newMeta) {
		setMeta(newMeta);
		return this;
	}

	/**
	 * Returns the meta data of the database.
	 *
	 * @return the meta data of the database
	 */
	public KdbxMeta getMeta() {
		return meta;
	}

	/**
	 * Sets the top level groups of the database.
	 *
	 * @param groups the top level groups of the database
	 */
	public void setGroups(final List<KdbxGroup> groups) {
		this.groups = groups;
	}

	/**
	 * Sets the top level groups of the database and returns this object for method chaining.
	 *
	 * @param newGroups the top level groups of the database
	 * @return this object
	 */
	public KdbxDatabase withGroups(final List<KdbxGroup> newGroups) {
		setGroups(newGroups);
		return this;
	}

	/**
	 * Returns the top level groups of the database.
	 *
	 * @return the top level groups of the database
	 */
	public List<KdbxGroup> getGroups() {
		return groups;
	}

	/**
	 * Sets the entries on root level of the database, which are not contained in a group.
	 *
	 * @param entries the entries on root level of the database, which are not contained in a group
	 */
	public void setEntries(final List<KdbxEntry> entries) {
		this.entries = entries;
	}

	/**
	 * Sets the entries on root level of the database, which are not contained in a group and returns this object for method chaining.
	 *
	 * @param newEntries the entries on root level of the database, which are not contained in a group
	 * @return this object
	 */
	public KdbxDatabase withEntries(final List<KdbxEntry> newEntries) {
		setEntries(newEntries);
		return this;
	}

	/**
	 * Returns the entries on root level of the database, which are not contained in a group.
	 *
	 * @return the entries on root level of the database, which are not contained in a group
	 */
	public List<KdbxEntry> getEntries() {
		return entries;
	}

	/**
	 * Returns the deletion times of deleted groups and entries by UUID.
	 *
	 * @return the deletion times of deleted groups and entries by UUID
	 */
	public Map<KdbxUUID, ZonedDateTime> getDeletedObjects() {
		return deletedObjects;
	}

	/**
	 * Searches a group by its UUID in all groups of the database including nested subgroups.
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
	 * Searches an entry by its UUID in the database and all groups including nested subgroups. History entries are not searched.
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
	 * Returns the path to a group or entry as list of UUIDs: from the top level group down to the searched object itself.
	 * For an entry on root level the path contains only the entry UUID.
	 *
	 * @param uuid UUID of the searched group or entry
	 * @return the UUID path or null if not found
	 */
	public List<KdbxUUID> getUuidPath(final KdbxUUID uuid) {
		for (final KdbxEntry entry : entries) {
			if (entry.getUuid().equals(uuid)) {
				final List<KdbxUUID> pathUuids = new ArrayList<>();
				pathUuids.add(entry.getUuid());
				return pathUuids;
			}
		}
		for (final KdbxGroup group : groups) {
			final List<KdbxUUID> pathUuids = group.getUuidPath(uuid);
			if (pathUuids != null) {
				return pathUuids;
			}
		}
		return null;
	}

	/**
	 * Returns all groups of the database including nested subgroups.
	 *
	 * @return new list of all groups
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
	 * Returns all entries of the database and all groups including nested subgroups. History entries are not included.
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

	/**
	 * Remembers the credentials as salted fingerprint to detect a change of the master key at the next write.
	 *
	 * @param compositeKeyHash hash of the composite key of the credentials
	 * @throws Exception if HMAC-SHA256 is not available
	 */
	void rememberCredentials(final byte[] compositeKeyHash) throws Exception {
		credentialsFingerprintSalt = new byte[32];
		new SecureRandom().nextBytes(credentialsFingerprintSalt);
		credentialsFingerprint = createCredentialsFingerprint(credentialsFingerprintSalt, compositeKeyHash);
	}

	/**
	 * Checks, whether the credentials are the same as those of the last read or write of this database.
	 *
	 * @param compositeKeyHash hash of the composite key of the credentials
	 * @return true for the same credentials, false for other or unknown credentials
	 * @throws Exception if HMAC-SHA256 is not available
	 */
	boolean isSameCredentials(final byte[] compositeKeyHash) throws Exception {
		if (credentialsFingerprint == null) {
			return false;
		} else {
			return MessageDigest.isEqual(credentialsFingerprint, createCredentialsFingerprint(credentialsFingerprintSalt, compositeKeyHash));
		}
	}

	/**
	 * Creates the salted fingerprint of a composite key hash.
	 *
	 * @param salt random salt
	 * @param compositeKeyHash hash of the composite key of the credentials
	 * @return HMAC-SHA256 of the composite key hash
	 * @throws Exception if HMAC-SHA256 is not available
	 */
	private static byte[] createCredentialsFingerprint(final byte[] salt, final byte[] compositeKeyHash) throws Exception {
		final Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
		return hmac.doFinal(compositeKeyHash);
	}

	/**
	 * Returns all entries of the database and all groups including nested subgroups and all history entries.
	 *
	 * @return new list of all entries including history entries
	 */
	public List<KdbxEntry> getAllEntriesIncludingHistory() {
		final List<KdbxEntry> entriesList = new ArrayList<>();
		for (final KdbxEntry entry : getAllEntries()) {
			addEntryWithHistory(entriesList, entry);
		}
		return entriesList;
	}

	/**
	 * Adds an entry and recursively its history entries to a list.
	 *
	 * @param entriesList list to add the entries
	 * @param entry the entry
	 */
	private static void addEntryWithHistory(final List<KdbxEntry> entriesList, final KdbxEntry entry) {
		entriesList.add(entry);
		for (final KdbxEntry historyEntry : entry.getHistory()) {
			addEntryWithHistory(entriesList, historyEntry);
		}
	}

	/**
	 * Validates the database and prepares it for writing.
	 * <p>
	 * Checks that all UUIDs of groups and entries are unique and rebuilds the binary attachments of the database from the attachments of all entries including history entries.
	 * Identical attachment data is stored only once. The attachment data is kept in the entries, so the database can be written again later.
	 *
	 * @throws Exception if UUIDs are duplicate or an attachment has no data
	 */
	public void validate() throws Exception {
		final Set<KdbxUUID> usedUuids = new HashSet<>();
		for (final KdbxGroup group : getAllGroups()) {
			if (!usedUuids.add(group.getUuid())) {
				throw new Exception("Group with duplicate UUID found: " + group.getUuid().toHex());
			}
			if (group.getIconID() != null) {
				try {
					KdbxConstants.KdbxStandardIcon.getById(group.getIconID());
				} catch (final Exception e) {
					throw new Exception("Invalid standard icon id found in group '" + group.getName() + "': " + group.getIconID(), e);
				}
			}
		}
		for (final KdbxEntry entry : getAllEntries()) {
			if (!usedUuids.add(entry.getUuid())) {
				throw new Exception("Entry with duplicate UUID found: " + entry.getUuid().toHex());
			}
			if (entry.getIconID() != null) {
				try {
					KdbxConstants.KdbxStandardIcon.getById(entry.getIconID());
				} catch (final Exception e) {
					throw new Exception("Invalid standard icon id found in entry '" + entry.getTitle() + "': " + entry.getIconID(), e);
				}
			}
		}

		// Only referenced binaries will be stored, including the attachments of history entries.
		// The same binary attachment data is stored only once.
		// The attachment data is kept in the entries, so the database can be written again later.
		final List<KdbxBinary> previousBinaryAttachments = getBinaryAttachments();
		final List<KdbxBinary> newBinaryAttachments = new ArrayList<>();
		final Map<ByteBuffer, Integer> binaryIdsByData = new HashMap<>();
		for (final KdbxEntry entry : getAllEntriesIncludingHistory()) {
			for (final KdbxEntryBinary entryBinary : entry.getBinaries()) {
				byte[] entryBinaryData = entryBinary.getData();
				if (entryBinaryData == null && entryBinary.getRefId() != null) {
					entryBinaryData = getBinaryAttachmentData(previousBinaryAttachments, entryBinary.getRefId());
				}
				if (entryBinaryData == null) {
					throw new Exception("Attachment '" + entryBinary.getKey() + "' of entry '" + entry.getTitle() + "' (" + entry.getUuid().toHex() + ") has no data");
				}
				Integer binaryId = binaryIdsByData.get(ByteBuffer.wrap(entryBinaryData));
				if (binaryId == null) {
					binaryId = newBinaryAttachments.size();
					newBinaryAttachments.add(new KdbxBinary().withId(binaryId).withCompressed(true).withData(Utilities.gzip(entryBinaryData)));
					binaryIdsByData.put(ByteBuffer.wrap(entryBinaryData), binaryId);
				}
				entryBinary.setRefId(binaryId);
			}
		}
		setBinaryAttachments(newBinaryAttachments);
	}

	/**
	 * Returns the uncompressed data of a binary attachment by its id.
	 *
	 * @param binaryAttachments the binary attachments
	 * @param binaryId id of the binary
	 * @return the uncompressed data or null if not found
	 * @throws Exception if decompression fails
	 */
	private static byte[] getBinaryAttachmentData(final List<KdbxBinary> binaryAttachments, final int binaryId) throws Exception {
		if (binaryAttachments != null) {
			for (final KdbxBinary binaryAttachment : binaryAttachments) {
				if (binaryAttachment.getId() == binaryId) {
					return binaryAttachment.isCompressed() ? Utilities.gunzip(binaryAttachment.getData()) : binaryAttachment.getData();
				}
			}
		}
		return null;
	}
}
