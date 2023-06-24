package de.soderer.utilities.kdbx;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import de.soderer.utilities.kdbx.data.KdbxBinary;
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
		database.validate();

		final Set<String> keyNamesToEncrypt = new HashSet<>();
		final KdbxMemoryProtection memoryProtection = database.getMeta().getMemoryProtection();
		if (memoryProtection.isProtectTitle()) {
			keyNamesToEncrypt.add("Title");
		}
		if (memoryProtection.isProtectUserName()) {
			keyNamesToEncrypt.add("UserName");
		}
		if (memoryProtection.isProtectPassword()) {
			keyNamesToEncrypt.add("Password");
		}
		if (memoryProtection.isProtectURL()) {
			keyNamesToEncrypt.add("URL");
		}
		if (memoryProtection.isProtectNotes()) {
			keyNamesToEncrypt.add("Notes");
		}
		keyNamesToEncrypt.add("KPRPC JSON");

		final Document document = Utilities.createNewDocument();
		final Node xmlDocumentRootNode = Utilities.appendNode(document, "KeePassFile");
		final Node metaNode = writeMetaNode(dataFormatVersionToStore, xmlDocumentRootNode, database.getMeta());
		writeRootNode(keyNamesToEncrypt, dataFormatVersionToStore, xmlDocumentRootNode, database);

		if (dataFormatVersionToStore.getMajorVersionNumber() < 4) {
			writeBinariesToMeta(metaNode, database.getBinaryAttachments());
		}

		System.out.println(new String(convertXML2ByteArray(document, StandardCharsets.UTF_8)));

		// TODO
		//if (dataFormatVersion.getMajorVersionNumber() < 4) {
		// writeBinariesToInnerHeaders

		//TODO write out header and data
	}

	public static byte[] convertXML2ByteArray(final Node pDocument, final Charset encoding) throws Exception {
		TransformerFactory transformerFactory = null;
		Transformer transformer = null;
		DOMSource domSource = null;
		StreamResult result = null;

		try {
			transformerFactory = TransformerFactory.newInstance();
			if (transformerFactory == null) {
				throw new Exception("TransformerFactory error");
			}

			transformer = transformerFactory.newTransformer();
			if (transformer == null) {
				throw new Exception("Transformer error");
			}

			if (encoding != null) {
				transformer.setOutputProperty(OutputKeys.ENCODING, encoding.name());
			} else {
				transformer.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
			}

			domSource = new DOMSource(pDocument);
			try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
				result = new StreamResult(outputStream);

				transformer.transform(domSource, result);

				return outputStream.toByteArray();
			}
		} catch (final TransformerFactoryConfigurationError e) {
			throw new Exception("TransformerFactoryConfigurationError", e);
		} catch (final TransformerConfigurationException e) {
			throw new Exception("TransformerConfigurationException", e);
		} catch (final TransformerException e) {
			throw new Exception("TransformerException", e);
		}
	}

	private Node writeMetaNode(final Version dataFormatVersion, final Node xmlDocumentRootNode, final KdbxMeta meta) {
		final Node metaNode = Utilities.appendNode(xmlDocumentRootNode, "Meta");
		if (meta.getGenerator() != null) {
			Utilities.appendTextValueNode(metaNode, "Generator", meta.getGenerator());
		}
		if (meta.getHeaderHash() != null) {
			Utilities.appendTextValueNode(metaNode, "HeaderHash", meta.getHeaderHash());
		}
		if (meta.getSettingsChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "SettingsChanged", formatDateTimeValue(dataFormatVersion, meta.getSettingsChanged()));
		}
		if (meta.getDatabaseName() != null) {
			Utilities.appendTextValueNode(metaNode, "DatabaseName", meta.getDatabaseName());
		}
		if (meta.getDatabaseNameChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "DatabaseNameChanged", formatDateTimeValue(dataFormatVersion, meta.getDatabaseNameChanged()));
		}
		if (meta.getDatabaseDescription() != null) {
			Utilities.appendTextValueNode(metaNode, "DatabaseDescription", meta.getDatabaseDescription());
		}
		if (meta.getDatabaseDescriptionChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "DatabaseDescriptionChanged", formatDateTimeValue(dataFormatVersion, meta.getDatabaseDescriptionChanged()));
		}
		if (meta.getDefaultUserName() != null) {
			Utilities.appendTextValueNode(metaNode, "DefaultUserName", meta.getDefaultUserName());
		}
		if (meta.getDefaultUserNameChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "DefaultUserNameChanged", formatDateTimeValue(dataFormatVersion, meta.getDefaultUserNameChanged()));
		}
		if (meta.getMaintenanceHistoryDays() > -1) {
			Utilities.appendTextValueNode(metaNode, "MaintenanceHistoryDays", formatIntegerValue(meta.getMaintenanceHistoryDays()));
		}
		if (meta.getColor() != null) {
			Utilities.appendTextValueNode(metaNode, "Color", meta.getColor());
		}
		if (meta.getMasterKeyChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "MasterKeyChanged", formatDateTimeValue(dataFormatVersion, meta.getMasterKeyChanged()));
		}
		if (meta.getMasterKeyChangeRec() > -1) {
			Utilities.appendTextValueNode(metaNode, "MasterKeyChangeRec", formatIntegerValue(meta.getMasterKeyChangeRec()));
		}
		if (meta.getMasterKeyChangeForce() > -1) {
			Utilities.appendTextValueNode(metaNode, "MasterKeyChangeForce", formatIntegerValue(meta.getMasterKeyChangeForce()));
		}
		Utilities.appendTextValueNode(metaNode, "RecycleBinEnabled", formatBooleanValue(meta.isRecycleBinEnabled()));
		if (meta.getRecycleBinUUID() != null) {
			Utilities.appendTextValueNode(metaNode, "RecycleBinUUID", formatKdbxUUIDValue(meta.getRecycleBinUUID()));
		}
		if (meta.getRecycleBinChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "RecycleBinChanged", formatDateTimeValue(dataFormatVersion, meta.getRecycleBinChanged()));
		}
		if (meta.getEntryTemplatesGroup() != null) {
			Utilities.appendTextValueNode(metaNode, "EntryTemplatesGroup", formatKdbxUUIDValue(meta.getEntryTemplatesGroup()));
		}
		if (meta.getEntryTemplatesGroupChanged() != null) {
			Utilities.appendTextValueNode(metaNode, "EntryTemplatesGroupChanged", formatDateTimeValue(dataFormatVersion, meta.getEntryTemplatesGroupChanged()));
		}
		if (meta.getHistoryMaxItems() > -1) {
			Utilities.appendTextValueNode(metaNode, "HistoryMaxItems", formatIntegerValue(meta.getHistoryMaxItems()));
		}
		if (meta.getHistoryMaxSize() > -1) {
			Utilities.appendTextValueNode(metaNode, "HistoryMaxSize", formatIntegerValue(meta.getHistoryMaxSize()));
		}
		if (meta.getLastSelectedGroup() != null) {
			Utilities.appendTextValueNode(metaNode, "LastSelectedGroup", formatKdbxUUIDValue(meta.getLastSelectedGroup()));
		}
		if (meta.getLastTopVisibleGroup() != null) {
			Utilities.appendTextValueNode(metaNode, "LastTopVisibleGroup", formatKdbxUUIDValue(meta.getLastTopVisibleGroup()));
		}
		writeMemoryProtectionNode(metaNode, meta.getMemoryProtection());
		writeCustomIcons(metaNode, meta.getCustomIcons());
		writeCustomData(dataFormatVersion, metaNode, meta.getCustomData());
		return metaNode;
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

	private void writeRootNode(final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node xmlDocumentRootNode, final KdbxDatabase database) {
		final Node rootNode = Utilities.appendNode(xmlDocumentRootNode, "Root");
		for (final KdbxGroup group : database.getGroups()) {
			writeGroupNode(keyNamesToEncrypt, dataFormatVersion, rootNode, group);
		}
		for (final KdbxEntry entry : database.getEntries()) {
			writeEntryNode(keyNamesToEncrypt, dataFormatVersion, rootNode, entry);
		}
	}

	private void writeBinariesToMeta(final Node metaNode, final List<KdbxBinary> binaryAttachments) throws Exception {
		final Node binariesNode = Utilities.appendNode(metaNode, "Binaries");
		for (final KdbxBinary binaryAttachment : binaryAttachments) {
			final Node binaryNode = Utilities.appendNode(binariesNode, "Binary");
			Utilities.appendTextValueNode(binaryNode, "ID", formatIntegerValue(binaryAttachment.getId()));
			Utilities.appendTextValueNode(binaryNode, "Compressed", formatBooleanValue(binaryAttachment.isCompressed()));
			byte[] valueBytes = binaryAttachment.getData();
			if (binaryAttachment.isCompressed()) {
				valueBytes = Utilities.gzip(valueBytes);
			}
			final String valueString = Base64.getEncoder().encodeToString(valueBytes);
			binaryNode.appendChild(binaryNode.getOwnerDocument().createTextNode(valueString));
		}
	}

	private void writeGroupNode(final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node baseNode, final KdbxGroup group) {
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
			writeGroupNode(keyNamesToEncrypt, dataFormatVersion, groupNode, subGroup);
		}

		for (final KdbxEntry entry : group.getEntries()) {
			writeEntryNode(keyNamesToEncrypt, dataFormatVersion, groupNode, entry);
		}

		if (group.getCustomIconUuid() != null) {
			Utilities.appendTextValueNode(groupNode, "CustomIconUUID", formatKdbxUUIDValue(group.getCustomIconUuid()));
		}

		if (group.getCustomData() != null) {
			writeCustomData(dataFormatVersion, groupNode, group.getCustomData());
		}
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

	private void writeEntryNode(final Set<String> keyNamesToEncrypt, final Version dataFormatVersion, final Node baseNode, final KdbxEntry entry) {
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
			String value = (String) itemEntry.getValue();
			if (keyNamesToEncrypt.contains(itemEntry.getKey())) {
				// TODO encrypt
				value = "to encrypt";
			}
			Utilities.appendTextValueNode(itemNode, "Value", value);
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

		if (entry.getCustomIconUuid() != null) {
			Utilities.appendTextValueNode(entryNode, "CustomIconUUID", formatKdbxUUIDValue(entry.getCustomIconUuid()));
		}

		if (entry.getCustomData() != null) {
			writeCustomData(dataFormatVersion, entryNode, entry.getCustomData());
		}
	}

	private void writeTimes(final Version dataFormatVersion, final Node baseNode, final KdbxTimes times) {
		final Node timesNode = Utilities.appendNode(baseNode, "Times");
		Utilities.appendTextValueNode(timesNode, "LastModificationTime", formatDateTimeValue(dataFormatVersion, times.getLastModificationTime()));
		Utilities.appendTextValueNode(timesNode, "CreationTime", formatDateTimeValue(dataFormatVersion, times.getCreationTime()));
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
