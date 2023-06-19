package de.soderer.utilities.kdbx;

import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.util.Utilities;

public class KdbxWriter implements AutoCloseable {
	OutputStream outputStream;

	public KdbxWriter(final OutputStream outputStream) {
		this.outputStream = outputStream;
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final char[] password) throws Exception {
		writeKdbxDatabase(database, new KdbxCredentials(password));
	}

	public void writeKdbxDatabase(final KdbxDatabase database, final KdbxCredentials credentials) throws Exception {
		validateDatabase(database);
		final Document document = Utilities.createNewDocument();
		final Node rootNode = Utilities.appendNode(document, "KeePass");
		writeMeta(rootNode, database.getMeta());
	}

	private void validateDatabase(final KdbxDatabase database) throws Exception {
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

	private void writeMeta(final Node rootNode, final KdbxMeta meta) {
		//        final NodeList childNodes = metaNode.getChildNodes();
		//        for (int i = 0; i < childNodes.getLength(); i++) {
		//            final Node childNode = childNodes.item(i);
		//            if (childNode.getNodeType() != Node.TEXT_NODE) {
		//                if ("Generator".equals(childNode.getNodeName())) {
		//  kdbxMeta.setGenerator(parseStringValue(childNode));
		//                } else if ("HeaderHash".equals(childNode.getNodeName())) {
		//  kdbxMeta.setHeaderHash(parseStringValue(childNode));
		//                } else if ("SettingsChanged".equals(childNode.getNodeName())) {
		//  kdbxMeta.setSettingsChanged(parseDateTimeValue(dataFormatVersion, childNode));
		//                } else if ("DatabaseName".equals(childNode.getNodeName())) {
		//  kdbxMeta.setDatabaseName(parseStringValue(childNode));
		//                } else if ("DatabaseNameChanged".equals(childNode.getNodeName())) {
		//  kdbxMeta.setDatabaseNameChanged(parseDateTimeValue(dataFormatVersion, childNode));
		//                } else if ("DatabaseDescription".equals(childNode.getNodeName())) {
		//  kdbxMeta.setDatabaseDescription(parseStringValue(childNode));
		//                } else if ("DatabaseDescriptionChanged".equals(childNode.getNodeName())) {
		//  kdbxMeta.setDatabaseDescriptionChanged(parseDateTimeValue(dataFormatVersion, childNode));
		//                } else if ("DefaultUserName".equals(childNode.getNodeName())) {
		//  kdbxMeta.setDefaultUserName(parseStringValue(childNode));
		//                } else if ("DefaultUserNameChanged".equals(childNode.getNodeName())) {
		//  kdbxMeta.setDefaultUserNameChanged(parseDateTimeValue(dataFormatVersion, childNode));
		//                } else if ("MaintenanceHistoryDays".equals(childNode.getNodeName())) {
		//  kdbxMeta.setMaintenanceHistoryDays(parseStringValue(childNode));
		//                } else if ("Color".equals(childNode.getNodeName())) {
		//  kdbxMeta.setColor(parseStringValue(childNode));
		//                } else if ("MasterKeyChanged".equals(childNode.getNodeName())) {
		//  kdbxMeta.setMasterKeyChanged(parseDateTimeValue(dataFormatVersion, childNode));
		//                } else if ("MasterKeyChangeRec".equals(childNode.getNodeName())) {
		//  kdbxMeta.setMasterKeyChangeRec(parseStringValue(childNode));
		//                } else if ("MasterKeyChangeForce".equals(childNode.getNodeName())) {
		//  kdbxMeta.setMasterKeyChangeForce(parseStringValue(childNode));
		//                } else if ("RecycleBinEnabled".equals(childNode.getNodeName())) {
		//  kdbxMeta.setRecycleBinEnabled(parseStringValue(childNode));
		//                } else if ("RecycleBinUUID".equals(childNode.getNodeName())) {
		//  kdbxMeta.setRecycleBinUUID(parseStringValue(childNode));
		//                } else if ("RecycleBinChanged".equals(childNode.getNodeName())) {
		//  kdbxMeta.setRecycleBinChanged(parseDateTimeValue(dataFormatVersion, childNode));
		//                } else if ("EntryTemplatesGroup".equals(childNode.getNodeName())) {
		//  kdbxMeta.setEntryTemplatesGroup(parseStringValue(childNode));
		//                } else if ("EntryTemplatesGroupChanged".equals(childNode.getNodeName())) {
		//  kdbxMeta.setEntryTemplatesGroupChanged(parseDateTimeValue(dataFormatVersion, childNode));
		//                } else if ("HistoryMaxItems".equals(childNode.getNodeName())) {
		//  kdbxMeta.setHistoryMaxItems(parseStringValue(childNode));
		//                } else if ("HistoryMaxSize".equals(childNode.getNodeName())) {
		//  kdbxMeta.setHistoryMaxSize(parseStringValue(childNode));
		//                } else if ("LastSelectedGroup".equals(childNode.getNodeName())) {
		//  kdbxMeta.setLastSelectedGroup(parseStringValue(childNode));
		//                } else if ("LastTopVisibleGroup".equals(childNode.getNodeName())) {
		//  kdbxMeta.setLastTopVisibleGroup(parseStringValue(childNode));
		//                } else if ("Binaries".equals(childNode.getNodeName())) {
		//  kdbxMeta.setBinaries(parseStringValue(childNode));
		//                } else if ("MemoryProtection".equals(childNode.getNodeName())) {
		//  kdbxMeta.setMemoryProtection(parseMemoryProtection(childNode));
		//                } else if ("CustomData".equals(childNode.getNodeName())) {
		//  kdbxMeta.setCustomData(parseCustomData(dataFormatVersion, childNode));
		//                } else {
		//                    throw new Exception("Unexpected meta attribute node name: " + childNode.getNodeName());
		//                }
		//            }
		//        }
		//        return kdbxMeta;
	}

	@Override
	public void close() throws Exception {
		if (outputStream != null) {
			outputStream.close();
		}
	}
}
