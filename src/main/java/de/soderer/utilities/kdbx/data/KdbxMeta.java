package de.soderer.utilities.kdbx.data;

import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class KdbxMeta {
	private String generator;
	private String headerHash;
	private ZonedDateTime settingsChanged;
	private String databaseName;
	private ZonedDateTime databaseNameChanged;
	private String databaseDescription;
	private ZonedDateTime databaseDescriptionChanged;
	private String defaultUserName;
	private ZonedDateTime defaultUserNameChanged;
	private int maintenanceHistoryDays;
	private String color;
	private ZonedDateTime masterKeyChanged;
	private int masterKeyChangeRec;
	private int masterKeyChangeForce;
	private boolean masterKeyChangeForceOnce;
	private boolean recycleBinEnabled;
	private KdbxUUID recycleBinUUID;
	private ZonedDateTime recycleBinChanged;
	private KdbxUUID entryTemplatesGroup;
	private ZonedDateTime entryTemplatesGroupChanged;
	private int historyMaxItems;
	private int historyMaxSize;
	private KdbxUUID lastSelectedGroup;
	private KdbxUUID lastTopVisibleGroup;
	private KdbxMemoryProtection memoryProtection;
	private List<KdbxCustomDataItem> customData;
	public Map<KdbxUUID, byte[]> customIcons = new LinkedHashMap<>();

	/**
	 * Name of the program, which created the kdbx file
	 */
	public void setGenerator(final String generator) {
		this.generator = generator;
	}

	public KdbxMeta withGenerator(final String newGenerator) {
		setGenerator(newGenerator);
		return this;
	}

	/**
	 * Name of the program, which created the kdbx file
	 */
	public String getGenerator() {
		return generator;
	}

	/**
	 * SHA-256 hash of the KDBX header data as BLOB.
	 * Only utilized in KDBX 3.1 or lower.
	 * MAY also be present in KDBX 4.0 or higher.
	 */
	public void setHeaderHash(final String headerHash) {
		this.headerHash = headerHash;
	}

	public KdbxMeta withHeaderHash(final String newHeaderHash) {
		setHeaderHash(newHeaderHash);
		return this;
	}

	/**
	 * SHA-256 hash of the KDBX header data as BLOB.
	 * Only utilized in KDBX 3.1 or lower.
	 * MAY also be present in KDBX 4.0 or higher.
	 */
	public String getHeaderHash() {
		return headerHash;
	}

	/**
	 *  Datetime of change of settings or meta  data change
	 *  May only be present in KDBX 4.0 or higher.
	 */
	public void setSettingsChanged(final ZonedDateTime settingsChanged) {
		this.settingsChanged = settingsChanged;
	}

	public KdbxMeta withSettingsChanged(final ZonedDateTime newSettingsChanged) {
		setSettingsChanged(newSettingsChanged);
		return this;
	}

	/**
	 *  Datetime of change of settings or meta  data change
	 *  May only be present in KDBX 4.0 or higher.
	 */
	public ZonedDateTime getSettingsChanged() {
		return settingsChanged;
	}

	/**
	 * Name of the database
	 */
	public void setDatabaseName(final String databaseName) {
		this.databaseName = databaseName;
	}

	public KdbxMeta withDatabaseName(final String newDatabaseName) {
		setDatabaseName(newDatabaseName);
		return this;
	}

	/**
	 * Name of the database
	 */
	public String getDatabaseName() {
		return databaseName;
	}

	/**
	 *  Datetime of database name change
	 */
	public void setDatabaseNameChanged(final ZonedDateTime databaseNameChanged) {
		this.databaseNameChanged = databaseNameChanged;
	}

	public KdbxMeta withDatabaseNameChanged(final ZonedDateTime newDatabaseNameChanged) {
		setDatabaseNameChanged(newDatabaseNameChanged);
		return this;
	}

	/**
	 *  Datetime of database name change
	 */
	public ZonedDateTime getDatabaseNameChanged() {
		return databaseNameChanged;
	}

	/**
	 *  Database description
	 */
	public void setDatabaseDescription(final String databaseDescription) {
		this.databaseDescription = databaseDescription;
	}

	public KdbxMeta withDatabaseDescription(final String newDatabaseDescription) {
		setDatabaseDescription(newDatabaseDescription);
		return this;
	}

	/**
	 *  Database description
	 */
	public String getDatabaseDescription() {
		return databaseDescription;
	}

	/**
	 *  Datetime of database description change
	 */
	public void setDatabaseDescriptionChanged(final ZonedDateTime databaseDescriptionChanged) {
		this.databaseDescriptionChanged = databaseDescriptionChanged;
	}

	public KdbxMeta withDatabaseDescriptionChanged(final ZonedDateTime newDatabaseDescriptionChanged) {
		setDatabaseDescriptionChanged(newDatabaseDescriptionChanged);
		return this;
	}

	/**
	 *  Datetime of database description change
	 */
	public ZonedDateTime getDatabaseDescriptionChanged() {
		return databaseDescriptionChanged;
	}

	/**
	 * Default username for new entries
	 */
	public void setDefaultUserName(final String defaultUserName) {
		this.defaultUserName = defaultUserName;
	}

	public KdbxMeta withDefaultUserName(final String newDefaultUserName) {
		setDefaultUserName(newDefaultUserName);
		return this;
	}

	/**
	 * Default username for new entries
	 */
	public String getDefaultUserName() {
		return defaultUserName;
	}

	/**
	 *  Datetime of default username change
	 */
	public void setDefaultUserNameChanged(final ZonedDateTime defaultUserNameChanged) {
		this.defaultUserNameChanged = defaultUserNameChanged;
	}

	public KdbxMeta withDefaultUserNameChanged(final ZonedDateTime newDefaultUserNameChanged) {
		setDefaultUserNameChanged(newDefaultUserNameChanged);
		return this;
	}

	/**
	 *  Datetime of default username change
	 */
	public ZonedDateTime getDefaultUserNameChanged() {
		return defaultUserNameChanged;
	}

	/**
	 * Maximum age in days of history entries
	 */
	public void setMaintenanceHistoryDays(final int maintenanceHistoryDays) {
		this.maintenanceHistoryDays = maintenanceHistoryDays;
	}

	public KdbxMeta withMaintenanceHistoryDays(final int newMaintenanceHistoryDays) {
		setMaintenanceHistoryDays(newMaintenanceHistoryDays);
		return this;
	}

	/**
	 * Maximum age in days of history entries
	 */
	public int getMaintenanceHistoryDays() {
		return maintenanceHistoryDays;
	}

	/**
	 * Color for GUI display of database
	 * Six-digit hexadecimal RGB color code with a # prefix character
	 */
	public void setColor(final String color) {
		this.color = color;
	}

	public KdbxMeta withColor(final String newColor) {
		setColor(newColor);
		return this;
	}

	/**
	 * Color for GUI display of database
	 * Six-digit hexadecimal RGB color code with a # prefix character
	 */
	public String getColor() {
		return color;
	}

	/**
	 * Datetime of last master key change
	 */
	public void setMasterKeyChanged(final ZonedDateTime masterKeyChanged) {
		this.masterKeyChanged = masterKeyChanged;
	}

	public KdbxMeta withMasterKeyChanged(final ZonedDateTime newMasterKeyChanged) {
		setMasterKeyChanged(newMasterKeyChanged);
		return this;
	}

	/**
	 * Datetime of last master key change
	 */
	public ZonedDateTime getMasterKeyChanged() {
		return masterKeyChanged;
	}

	/**
	 * Master key expiration in days for change recommendation (-1 => Unlimited)
	 */
	public void setMasterKeyChangeRec(final int masterKeyChangeRec) {
		this.masterKeyChangeRec = masterKeyChangeRec;
	}

	public KdbxMeta withMasterKeyChangeRec(final int newMasterKeyChangeRec) {
		setMasterKeyChangeRec(newMasterKeyChangeRec);
		return this;
	}

	/**
	 * Master key expiration in days for change recommendation (-1 => Unlimited)
	 */
	public int getMasterKeyChangeRec() {
		return masterKeyChangeRec;
	}

	/**
	 * Master key expiration in days for forced change (-1 => Unlimited)
	 */
	public void setMasterKeyChangeForce(final int masterKeyChangeForce) {
		this.masterKeyChangeForce = masterKeyChangeForce;
	}

	public KdbxMeta withMasterKeyChangeForce(final int newMasterKeyChangeForce) {
		setMasterKeyChangeForce(newMasterKeyChangeForce);
		return this;
	}

	/**
	 * Master key expiration in days for forced change (-1 => Unlimited)
	 */
	public int getMasterKeyChangeForce() {
		return masterKeyChangeForce;
	}

	/**
	 * Enforce master key change on next database open
	 */
	public void setMasterKeyChangeForceOnce(final boolean masterKeyChangeForceOnce) {
		this.masterKeyChangeForceOnce = masterKeyChangeForceOnce;
	}

	public KdbxMeta withMasterKeyChangeForceOnce(final boolean newMasterKeyChangeForceOnce) {
		setMasterKeyChangeForceOnce(newMasterKeyChangeForceOnce);
		return this;
	}

	/**
	 * Enforce master key change on next database open
	 */
	public boolean isMasterKeyChangeForceOnce() {
		return masterKeyChangeForceOnce;
	}

	/**
	 * Activation state of the recycling bin
	 */
	public void setRecycleBinEnabled(final boolean recycleBinEnabled) {
		this.recycleBinEnabled = recycleBinEnabled;
		if (recycleBinEnabled && recycleBinUUID == null) {
			recycleBinUUID = new KdbxUUID();
		}
	}

	public KdbxMeta withRecycleBinEnabled(final boolean newRecycleBinEnabled) {
		setRecycleBinEnabled(newRecycleBinEnabled);
		return this;
	}

	/**
	 * Activation state of the recycling bin
	 */
	public boolean isRecycleBinEnabled() {
		return recycleBinEnabled;
	}

	/**
	 * UUID of the recycling bin group
	 */
	public void setRecycleBinUUID(final KdbxUUID recycleBinUUID) {
		this.recycleBinUUID = recycleBinUUID;
	}

	public KdbxMeta withRecycleBinUUID(final KdbxUUID newRecycleBinUUID) {
		setRecycleBinUUID(newRecycleBinUUID);
		return this;
	}

	/**
	 * UUID of the recycling bin group
	 */
	public KdbxUUID getRecycleBinUUID() {
		return recycleBinUUID;
	}

	/**
	 * Datetime of recycling bin group change
	 */
	public void setRecycleBinChanged(final ZonedDateTime recycleBinChanged) {
		this.recycleBinChanged = recycleBinChanged;
	}

	public KdbxMeta withRecycleBinChanged(final ZonedDateTime newRecycleBinChanged) {
		setRecycleBinChanged(newRecycleBinChanged);
		return this;
	}

	/**
	 * Datetime of recycling bin group change
	 */
	public ZonedDateTime getRecycleBinChanged() {
		return recycleBinChanged;
	}

	/**
	 * UUID of the group containing entry templates
	 */
	public void setEntryTemplatesGroup(final KdbxUUID entryTemplatesGroup) {
		this.entryTemplatesGroup = entryTemplatesGroup;
	}

	public KdbxMeta withEntryTemplatesGroup(final KdbxUUID newEntryTemplatesGroup) {
		setEntryTemplatesGroup(newEntryTemplatesGroup);
		return this;
	}

	/**
	 * UUID of the group containing entry templates
	 */
	public KdbxUUID getEntryTemplatesGroup() {
		return entryTemplatesGroup;
	}

	/**
	 * Datetime of entry templates group change
	 */
	public void setEntryTemplatesGroupChanged(final ZonedDateTime entryTemplatesGroupChanged) {
		this.entryTemplatesGroupChanged = entryTemplatesGroupChanged;
	}

	public KdbxMeta withEntryTemplatesGroupChanged(final ZonedDateTime newEntryTemplatesGroupChanged) {
		setEntryTemplatesGroupChanged(newEntryTemplatesGroupChanged);
		return this;
	}

	/**
	 * Datetime of entry templates group change
	 */
	public ZonedDateTime getEntryTemplatesGroupChanged() {
		return entryTemplatesGroupChanged;
	}

	/**
	 * Maximum number of items in the history of entries
	 */
	public void setHistoryMaxItems(final int historyMaxItems) {
		this.historyMaxItems = historyMaxItems;
	}

	public KdbxMeta withHistoryMaxItems(final int newHistoryMaxItems) {
		setHistoryMaxItems(newHistoryMaxItems);
		return this;
	}

	/**
	 * Maximum number of items in the history of entries
	 */
	public int getHistoryMaxItems() {
		return historyMaxItems;
	}

	/**
	 * Maximum size in bytes of items in the history of entries
	 */
	public void setHistoryMaxSize(final int historyMaxSize) {
		this.historyMaxSize = historyMaxSize;
	}

	public KdbxMeta withHistoryMaxSize(final int newHistoryMaxSize) {
		setHistoryMaxSize(newHistoryMaxSize);
		return this;
	}

	/**
	 * Maximum size in bytes of items in the history of entries
	 */
	public int getHistoryMaxSize() {
		return historyMaxSize;
	}

	/**
	 * UUID of the last selected group
	 */
	public void setLastSelectedGroup(final KdbxUUID lastSelectedGroup) {
		this.lastSelectedGroup = lastSelectedGroup;
	}

	public KdbxMeta withLastSelectedGroup(final KdbxUUID newLastSelectedGroup) {
		setLastSelectedGroup(newLastSelectedGroup);
		return this;
	}

	/**
	 * UUID of the last selected group
	 */
	public KdbxUUID getLastSelectedGroup() {
		return lastSelectedGroup;
	}

	/**
	 * UUID of the last scroll visible group
	 */
	public void setLastTopVisibleGroup(final KdbxUUID lastTopVisibleGroup) {
		this.lastTopVisibleGroup = lastTopVisibleGroup;
	}

	public KdbxMeta withLastTopVisibleGroup(final KdbxUUID newLastTopVisibleGroup) {
		setLastTopVisibleGroup(newLastTopVisibleGroup);
		return this;
	}

	/**
	 * UUID of the last scroll visible group
	 */
	public KdbxUUID getLastTopVisibleGroup() {
		return lastTopVisibleGroup;
	}

	/**
	 * Structure containing configuration of value protection
	 */
	public void setMemoryProtection(final KdbxMemoryProtection memoryProtection) {
		this.memoryProtection = memoryProtection;
	}

	public KdbxMeta withMemoryProtection(final KdbxMemoryProtection newMemoryProtection) {
		setMemoryProtection(newMemoryProtection);
		return this;
	}

	/**
	 * Structure containing configuration of value protection
	 */
	public KdbxMemoryProtection getMemoryProtection() {
		if (memoryProtection == null) {
			memoryProtection = new KdbxMemoryProtection();
		}
		return memoryProtection;
	}

	/**
	 * Binary data items of stored files.
	 * Only utilized in KDBX 3.1 or lower.
	 * MAY not be present in KDBX 4.0 or higher.
	 */
	public void setCustomData(final List<KdbxCustomDataItem> customData) {
		this.customData = customData;
	}

	public KdbxMeta withCustomData(final List<KdbxCustomDataItem> newCustomData) {
		setCustomData(newCustomData);
		return this;
	}

	/**
	 * Binary data items of stored files.
	 * Only utilized in KDBX 3.1 or lower.
	 * MAY not be present in KDBX 4.0 or higher.
	 */
	public List<KdbxCustomDataItem> getCustomData() {
		return customData;
	}

	/**
	 * Binary data of custom configured icons
	 */
	public void setCustomIcons(final Map<KdbxUUID, byte[]> customIcons) {
		this.customIcons = customIcons;
	}

	public KdbxMeta withCustomIcons(final Map<KdbxUUID, byte[]> newCustomIcons) {
		setCustomIcons(newCustomIcons);
		return this;
	}

	/**
	 * Binary data of custom configured icons
	 */
	public Map<KdbxUUID, byte[]> getCustomIcons() {
		return customIcons;
	}
}
