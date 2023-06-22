package de.soderer.utilities.kdbx;

import java.io.OutputStream;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxMemoryProtection;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.util.Utilities;
import de.soderer.utilities.kdbx.util.Version;

public class KdbxWriter implements AutoCloseable {
	OutputStream outputStream;

	public KdbxWriter(final OutputStream outputStream) {
		this.outputStream = outputStream;
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final char[] password) throws Exception {
		writeKdbxDatabase(database, new Version(4, 0, 0), new KdbxCredentials(password));
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final Version dataFormatVersionToStore, final char[] password) throws Exception {
		writeKdbxDatabase(database, dataFormatVersionToStore, new KdbxCredentials(password));
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final KdbxCredentials credentials) throws Exception {
		writeKdbxDatabase(database, new Version(4, 0, 0), credentials);
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final Version dataFormatVersionToStore, final KdbxCredentials credentials) throws Exception {
		validateDatabase(database, dataFormatVersionToStore);
		final Document document = Utilities.createNewDocument();
		final Node xmlDocumentRootNode = Utilities.appendNode(document, "KeePass");
		writeMetaNode(dataFormatVersionToStore, xmlDocumentRootNode, database.getMeta());
		writeRootNode(dataFormatVersionToStore, xmlDocumentRootNode, database);
	}

	private void validateDatabase(final KdbxDatabase database, final Version version) throws Exception {
		final Set<KdbxUUID> usedUuids = new HashSet<>();
		for (final KdbxGroup group : database.getAllGroups()) {
			if (!usedUuids.add(group.getUuid())) {
				throw new Exception("Group with duplicate UUID found: " + group.getUuid().toHex());
			}
		}
		for (final KdbxEntry entry : database.getAllEntries()) {
			if (!usedUuids.add(entry.getUuid())) {
				throw new Exception("Entry with duplicate UUID found: " + entry.getUuid().toHex());
			}
		}
	}

	private void writeMetaNode(final Version dataFormatVersionToStore, final Node xmlDocumentRootNode, final KdbxMeta meta) {
		final Node metaNode = Utilities.appendNode(xmlDocumentRootNode, "Meta");
		Utilities.appendTextValueNode(metaNode, "Generator", meta.getGenerator());
		Utilities.appendTextValueNode(metaNode, "HeaderHash", meta.getHeaderHash());
		Utilities.appendTextValueNode(metaNode, "SettingsChanged", formatDateTimeValue(dataFormatVersionToStore, meta.getSettingsChanged()));
		Utilities.appendTextValueNode(metaNode, "DatabaseName", meta.getDatabaseName());
		Utilities.appendTextValueNode(metaNode, "DatabaseNameChanged", formatDateTimeValue(dataFormatVersionToStore, meta.getDatabaseNameChanged()));
		Utilities.appendTextValueNode(metaNode, "DatabaseDescription", meta.getDatabaseDescription());
		Utilities.appendTextValueNode(metaNode, "DatabaseDescriptionChanged", formatDateTimeValue(dataFormatVersionToStore, meta.getDatabaseDescriptionChanged()));
		Utilities.appendTextValueNode(metaNode, "DefaultUserName", meta.getDefaultUserName());
		Utilities.appendTextValueNode(metaNode, "DefaultUserNameChanged", formatDateTimeValue(dataFormatVersionToStore, meta.getDefaultUserNameChanged()));
		Utilities.appendTextValueNode(metaNode, "MaintenanceHistoryDays", formatIntegerValue(meta.getMaintenanceHistoryDays()));
		Utilities.appendTextValueNode(metaNode, "Color", meta.getColor());
		Utilities.appendTextValueNode(metaNode, "MasterKeyChanged", formatDateTimeValue(dataFormatVersionToStore, meta.getMasterKeyChanged()));
		Utilities.appendTextValueNode(metaNode, "MasterKeyChangeRec", formatIntegerValue(meta.getMasterKeyChangeRec()));
		Utilities.appendTextValueNode(metaNode, "MasterKeyChangeForce", formatIntegerValue(meta.getMasterKeyChangeForce()));
		Utilities.appendTextValueNode(metaNode, "RecycleBinEnabled", formatBooleanValue(meta.isRecycleBinEnabled()));
		Utilities.appendTextValueNode(metaNode, "RecycleBinUUID", formatKdbxUUIDValue(meta.getRecycleBinUUID()));
		Utilities.appendTextValueNode(metaNode, "RecycleBinChanged", formatDateTimeValue(dataFormatVersionToStore, meta.getRecycleBinChanged()));
		Utilities.appendTextValueNode(metaNode, "EntryTemplatesGroup", formatKdbxUUIDValue(meta.getEntryTemplatesGroup()));
		Utilities.appendTextValueNode(metaNode, "EntryTemplatesGroupChanged", formatDateTimeValue(dataFormatVersionToStore, meta.getEntryTemplatesGroupChanged()));
		Utilities.appendTextValueNode(metaNode, "HistoryMaxItems", formatIntegerValue(meta.getHistoryMaxItems()));
		Utilities.appendTextValueNode(metaNode, "HistoryMaxSize", formatIntegerValue(meta.getHistoryMaxSize()));
		Utilities.appendTextValueNode(metaNode, "LastSelectedGroup", formatKdbxUUIDValue(meta.getLastSelectedGroup()));
		Utilities.appendTextValueNode(metaNode, "LastTopVisibleGroup", formatKdbxUUIDValue(meta.getLastTopVisibleGroup()));
		Utilities.appendTextValueNode(metaNode, "Binaries", meta.getBinaries());
		writeMemoryProtectionNode(metaNode, meta.getMemoryProtection());
		Utilities.appendTextValueNode(metaNode, "CustomData", meta.getCustomData());
		Utilities.appendTextValueNode(metaNode, "CustomIcons", meta.getCustomIcons());
	}

	private void writeMemoryProtectionNode(final Node metaNode, final KdbxMemoryProtection memoryProtection) {
		final Node memoryProtectionNode = Utilities.appendNode(metaNode, "MemoryProtection");
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectTitle", formatBooleanValue(memoryProtection.isProtectTitle()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectUserName", formatBooleanValue(memoryProtection.isProtectUserName()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectPassword", formatBooleanValue(memoryProtection.isProtectPassword()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectURL", formatBooleanValue(memoryProtection.isProtectURL()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectNotes", formatBooleanValue(memoryProtection.isProtectNotes()));
	}

	private void writeRootNode(final Version dataFormatVersionToStore, final Node xmlDocumentRootNode, final KdbxDatabase database) {
		final Node rootNode = Utilities.appendNode(xmlDocumentRootNode, "Root");
		for (final KdbxGroup group : database.getGroups()) {
			writeRootNode(rootNode, group);
		}
	}

	private void writeRootNode(final Node rootNode, final KdbxGroup group) {
		final Node groupNode = Utilities.appendNode(rootNode, "Group");
		Utilities.appendTextValueNode(groupNode, "UUID", formatKdbxUUIDValue(group.getUuid()));
		Utilities.appendTextValueNode(groupNode, "Name", group.getName());
		Utilities.appendTextValueNode(groupNode, "Notes", group.getNotes());
		Utilities.appendTextValueNode(groupNode, "IconID", formatIntegerValue(group.getIconID()));
		Utilities.appendTextValueNode(groupNode, "IsExpanded", formatBooleanValue(group.isExpanded()));
		Utilities.appendTextValueNode(groupNode, "DefaultAutoTypeSequence", group.getDefaultAutoTypeSequence());
		Utilities.appendTextValueNode(groupNode, "EnableAutoType", formatBooleanValue(group.isEnableAutoType()));
		Utilities.appendTextValueNode(groupNode, "EnableSearching", formatBooleanValue(group.isEnableSearching()));
		Utilities.appendTextValueNode(groupNode, "LastTopVisibleEntry", formatKdbxUUIDValue(group.getLastTopVisibleEntry()));
		Utilities.appendTextValueNode(groupNode, "Times", group.getTimes());
		for (final KdbxGroup subGroup : group.getGroups()) {
			writeGroupNode(groupNode, subGroup);
		}
		for (final KdbxEntry entry : group.getEntries()) {
			writeEntryNode(groupNode, entry);
		}
		Utilities.appendTextValueNode(groupNode, "CustomIconUUID", formatKdbxUUIDValue(group.getCustomIconUuid()));
		Utilities.appendTextValueNode(groupNode, "CustomData", group.getCustomData());
	}

	private String formatDateTimeValue(final Version kdbxVersion, final ZonedDateTime dateTimeValue) {
		if (dateTimeValue == null ) {
			return "";
		} else if (kdbxVersion.getMajorVersionNumber() < 4) {
			return DateTimeFormatter.ISO_DATE_TIME.format(dateTimeValue);
		} else {
			final Duration duration = Duration.between(ZonedDateTime.of(1, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC")), dateTimeValue);
			final long elapsedSeconds = duration.getSeconds();
			return Base64.getEncoder().encodeToString(Utilities.getLittleEndianBytes(elapsedSeconds));
		}
	}

	private String formatIntegerValue(final int value) {
		return Integer.toString(value);
	}

	private String formatBooleanValue(final boolean value) {
		return value ? "True" : "False";
	}

	private String formatKdbxUUIDValue(final KdbxUUID uuid) {
		return uuid.toBase64();
	}

	@Override
	public void close() throws Exception {
		if (outputStream != null) {
			outputStream.close();
		}
	}
}
