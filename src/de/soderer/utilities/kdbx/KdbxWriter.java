package de.soderer.utilities.kdbx;

import java.io.OutputStream;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import de.soderer.utilities.kdbx.data.KdbxCustomDataItem;
import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxEntryBinary;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxMemoryProtection;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxTimes;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.util.Utilities;
import de.soderer.utilities.kdbx.util.Version;

/**
 * Binary attachments
 * The same data should not be stored multiple times.
 * Dataversion <= 3.1 --> stored in KdbxMeta binaries
 * Dataversion >= 4.0 --> stored in KdbxInnerHeaderType.BINARY_ATTACHMENT
 */
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
		// TODO: check IconIDs
		// TODO: check binary attachments
	}

	private void writeMetaNode(final Version dataFormatVersion, final Node xmlDocumentRootNode, final KdbxMeta meta) {
		final Node metaNode = Utilities.appendNode(xmlDocumentRootNode, "Meta");
		Utilities.appendTextValueNode(metaNode, "Generator", meta.getGenerator());
		Utilities.appendTextValueNode(metaNode, "HeaderHash", meta.getHeaderHash());
		Utilities.appendTextValueNode(metaNode, "SettingsChanged", formatDateTimeValue(dataFormatVersion, meta.getSettingsChanged()));
		Utilities.appendTextValueNode(metaNode, "DatabaseName", meta.getDatabaseName());
		Utilities.appendTextValueNode(metaNode, "DatabaseNameChanged", formatDateTimeValue(dataFormatVersion, meta.getDatabaseNameChanged()));
		Utilities.appendTextValueNode(metaNode, "DatabaseDescription", meta.getDatabaseDescription());
		Utilities.appendTextValueNode(metaNode, "DatabaseDescriptionChanged", formatDateTimeValue(dataFormatVersion, meta.getDatabaseDescriptionChanged()));
		Utilities.appendTextValueNode(metaNode, "DefaultUserName", meta.getDefaultUserName());
		Utilities.appendTextValueNode(metaNode, "DefaultUserNameChanged", formatDateTimeValue(dataFormatVersion, meta.getDefaultUserNameChanged()));
		Utilities.appendTextValueNode(metaNode, "MaintenanceHistoryDays", formatIntegerValue(meta.getMaintenanceHistoryDays()));
		Utilities.appendTextValueNode(metaNode, "Color", meta.getColor());
		Utilities.appendTextValueNode(metaNode, "MasterKeyChanged", formatDateTimeValue(dataFormatVersion, meta.getMasterKeyChanged()));
		Utilities.appendTextValueNode(metaNode, "MasterKeyChangeRec", formatIntegerValue(meta.getMasterKeyChangeRec()));
		Utilities.appendTextValueNode(metaNode, "MasterKeyChangeForce", formatIntegerValue(meta.getMasterKeyChangeForce()));
		Utilities.appendTextValueNode(metaNode, "RecycleBinEnabled", formatBooleanValue(meta.isRecycleBinEnabled()));
		Utilities.appendTextValueNode(metaNode, "RecycleBinUUID", formatKdbxUUIDValue(meta.getRecycleBinUUID()));
		Utilities.appendTextValueNode(metaNode, "RecycleBinChanged", formatDateTimeValue(dataFormatVersion, meta.getRecycleBinChanged()));
		Utilities.appendTextValueNode(metaNode, "EntryTemplatesGroup", formatKdbxUUIDValue(meta.getEntryTemplatesGroup()));
		Utilities.appendTextValueNode(metaNode, "EntryTemplatesGroupChanged", formatDateTimeValue(dataFormatVersion, meta.getEntryTemplatesGroupChanged()));
		Utilities.appendTextValueNode(metaNode, "HistoryMaxItems", formatIntegerValue(meta.getHistoryMaxItems()));
		Utilities.appendTextValueNode(metaNode, "HistoryMaxSize", formatIntegerValue(meta.getHistoryMaxSize()));
		Utilities.appendTextValueNode(metaNode, "LastSelectedGroup", formatKdbxUUIDValue(meta.getLastSelectedGroup()));
		Utilities.appendTextValueNode(metaNode, "LastTopVisibleGroup", formatKdbxUUIDValue(meta.getLastTopVisibleGroup()));
		// TODO
		//		Utilities.appendTextValueNode(metaNode, "Binaries", meta.getBinaries());
		writeMemoryProtectionNode(metaNode, meta.getMemoryProtection());
		writeCustomData(dataFormatVersion, metaNode, meta.getCustomData());
		writeCustomIcons(metaNode, meta.getCustomIcons());
	}

	private void writeCustomIcons(final Node metaNode, final Map<KdbxUUID, byte[]> customIcons) {
		final Node customIconsNode = Utilities.appendNode(metaNode, "CustomIcons");
		for (final Entry<KdbxUUID, byte[]> customIcon : customIcons.entrySet()) {
			final Node iconNode = Utilities.appendNode(customIconsNode, "Icon");
			Utilities.appendTextValueNode(iconNode, "UUID", formatKdbxUUIDValue(customIcon.getKey()));
			Utilities.appendTextValueNode(iconNode, "Data", Base64.getEncoder().encodeToString(customIcon.getValue()));
		}
	}

	private void writeMemoryProtectionNode(final Node metaNode, final KdbxMemoryProtection memoryProtection) {
		final Node memoryProtectionNode = Utilities.appendNode(metaNode, "MemoryProtection");
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectTitle", formatBooleanValue(memoryProtection.isProtectTitle()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectUserName", formatBooleanValue(memoryProtection.isProtectUserName()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectPassword", formatBooleanValue(memoryProtection.isProtectPassword()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectURL", formatBooleanValue(memoryProtection.isProtectURL()));
		Utilities.appendTextValueNode(memoryProtectionNode, "ProtectNotes", formatBooleanValue(memoryProtection.isProtectNotes()));
	}

	private void writeRootNode(final Version dataFormatVersion, final Node xmlDocumentRootNode, final KdbxDatabase database) {
		final Node rootNode = Utilities.appendNode(xmlDocumentRootNode, "Root");
		for (final KdbxGroup group : database.getGroups()) {
			writeGroupNode(dataFormatVersion, rootNode, group);
		}
		for (final KdbxEntry entry : database.getEntries()) {
			writeEntryNode(dataFormatVersion, rootNode, entry);
		}
	}

	private void writeGroupNode(final Version dataFormatVersion, final Node baseNode, final KdbxGroup group) {
		final Node groupNode = Utilities.appendNode(baseNode, "Group");
		Utilities.appendTextValueNode(groupNode, "UUID", formatKdbxUUIDValue(group.getUuid()));
		Utilities.appendTextValueNode(groupNode, "Name", group.getName());
		Utilities.appendTextValueNode(groupNode, "Notes", group.getNotes());
		Utilities.appendTextValueNode(groupNode, "IconID", formatIntegerValue(group.getIconID()));
		Utilities.appendTextValueNode(groupNode, "IsExpanded", formatBooleanValue(group.isExpanded()));
		Utilities.appendTextValueNode(groupNode, "DefaultAutoTypeSequence", group.getDefaultAutoTypeSequence());
		Utilities.appendTextValueNode(groupNode, "EnableAutoType", formatBooleanValue(group.isEnableAutoType()));
		Utilities.appendTextValueNode(groupNode, "EnableSearching", formatBooleanValue(group.isEnableSearching()));
		Utilities.appendTextValueNode(groupNode, "LastTopVisibleEntry", formatKdbxUUIDValue(group.getLastTopVisibleEntry()));

		writeTimes(dataFormatVersion, groupNode, group.getTimes());

		for (final KdbxGroup subGroup : group.getGroups()) {
			writeGroupNode(dataFormatVersion, groupNode, subGroup);
		}

		for (final KdbxEntry entry : group.getEntries()) {
			writeEntryNode(dataFormatVersion, groupNode, entry);
		}

		Utilities.appendTextValueNode(groupNode, "CustomIconUUID", formatKdbxUUIDValue(group.getCustomIconUuid()));

		writeCustomData(dataFormatVersion, groupNode, group.getCustomData());
	}

	private void writeCustomData(final Version dataFormatVersion, final Node baseNode, final List<KdbxCustomDataItem> customData) {
		final Node customDataNode = Utilities.appendNode(baseNode, "CustomData");
		for (final KdbxCustomDataItem customDataItem : customData) {
			final Node customDataItemNode = Utilities.appendNode(customDataNode, "Item");
			Utilities.appendTextValueNode(customDataItemNode, "Key", customDataItem.getKey());
			Utilities.appendTextValueNode(customDataItemNode, "Value", customDataItem.getValue());
			Utilities.appendTextValueNode(customDataItemNode, "LastModificationTime", formatDateTimeValue(dataFormatVersion, customDataItem.getLastModificationTime()));
		}
	}

	private void writeEntryNode(final Version dataFormatVersion, final Node baseNode, final KdbxEntry entry) {
		final Node entryNode = Utilities.appendNode(baseNode, "Entry");
		Utilities.appendTextValueNode(entryNode, "UUID", formatKdbxUUIDValue(entry.getUuid()));
		Utilities.appendTextValueNode(entryNode, "IconID", formatIntegerValue(entry.getIconID()));
		Utilities.appendTextValueNode(entryNode, "ForegroundColor", entry.getForegroundColor());
		Utilities.appendTextValueNode(entryNode, "BackgroundColor", entry.getBackgroundColor());
		Utilities.appendTextValueNode(entryNode, "OverrideURL", entry.getOverrideURL());
		Utilities.appendTextValueNode(entryNode, "Tags", entry.getTags());

		writeTimes(dataFormatVersion, entryNode, entry.getTimes());

		for (final Entry<String, Object> itemEntry : entry.getItems().entrySet()) {
			final Node itemNode = Utilities.appendNode(entryNode, "String");
			Utilities.appendTextValueNode(itemNode, "Key", itemEntry.getKey());
			Utilities.appendTextValueNode(itemNode, "Value", (String) itemEntry.getValue());
			// TODO encrypt
		}

		for (final KdbxEntryBinary entryBinary : entry.getBinaries()) {
			// TODO
		}

		final Node autoTypeNode = Utilities.appendNode(entryNode, "AutoType");
		Utilities.appendTextValueNode(autoTypeNode, "Enabled", formatBooleanValue(entry.isAutoTypeEnabled()));
		Utilities.appendTextValueNode(autoTypeNode, "DataTransferObfuscation", entry.getAutoTypeDataTransferObfuscation());
		Utilities.appendTextValueNode(autoTypeNode, "DefaultSequence", entry.getAutoTypeDefaultSequence());
		final Node autoTypeAssociationNode = Utilities.appendNode(entryNode, "Association");
		Utilities.appendTextValueNode(autoTypeAssociationNode, "Window", entry.getAutoTypeAssociationWindow());
		Utilities.appendTextValueNode(autoTypeAssociationNode, "KeystrokeSequence", entry.getAutoTypeAssociationKeystrokeSequence());

		final Node historyNode = Utilities.appendNode(entryNode, "History");
		Utilities.appendTextValueNode(historyNode, "Entry", formatBooleanValue(entry.isAutoTypeEnabled()));

		Utilities.appendTextValueNode(entryNode, "CustomIconUUID", formatKdbxUUIDValue(entry.getCustomIconUuid()));

		writeCustomData(dataFormatVersion, entryNode, entry.getCustomData());
	}

	private void writeTimes(final Version dataFormatVersion, final Node baseNode, final KdbxTimes times) {
		final Node timesNode = Utilities.appendNode(baseNode, "Times");
		Utilities.appendTextValueNode(timesNode, "CreationTime", formatDateTimeValue(dataFormatVersion, times.getCreationTime()));
		Utilities.appendTextValueNode(timesNode, "LastModificationTime", formatDateTimeValue(dataFormatVersion, times.getLastModificationTime()));
		Utilities.appendTextValueNode(timesNode, "LastAccessTime", formatDateTimeValue(dataFormatVersion, times.getLastAccessTime()));
		Utilities.appendTextValueNode(timesNode, "ExpiryTime", formatDateTimeValue(dataFormatVersion, times.getExpiryTime()));
		Utilities.appendTextValueNode(timesNode, "Expires", formatBooleanValue(times.isExpires()));
		Utilities.appendTextValueNode(timesNode, "UsageCount", formatIntegerValue(times.getUsageCount()));
		Utilities.appendTextValueNode(timesNode, "LocationChanged", formatDateTimeValue(dataFormatVersion, times.getLocationChanged()));
	}

	private String formatDateTimeValue(final Version dataFormatVersion, final ZonedDateTime dateTimeValue) {
		if (dateTimeValue == null ) {
			return "";
		} else if (dataFormatVersion.getMajorVersionNumber() < 4) {
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
