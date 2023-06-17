package de.soderer.utilities.kdbx.data;

import java.time.ZonedDateTime;
import java.util.List;

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
	private String maintenanceHistoryDays;
	private String color;
	private ZonedDateTime masterKeyChanged;
	private String masterKeyChangeRec;
	private String masterKeyChangeForce;
	private String recycleBinEnabled;
	private String recycleBinUUID;
	private ZonedDateTime recycleBinChanged;
	private String entryTemplatesGroup;
	private ZonedDateTime entryTemplatesGroupChanged;
	private String historyMaxItems;
	private String historyMaxSize;
	private String lastSelectedGroup;
	private String lastTopVisibleGroup;
	private String binaries;
	private KdbxMemoryProtection memoryProtection;
	private List<KdbxCustomDataItem> customData;

	public String getGenerator() {
		return generator;
	}

	public KdbxMeta setGenerator(final String generator) {
		this.generator = generator;
		return this;
	}

	public String getHeaderHash() {
		return headerHash;
	}

	public KdbxMeta setHeaderHash(final String headerHash) {
		this.headerHash = headerHash;
		return this;
	}

	public ZonedDateTime getSettingsChanged() {
		return settingsChanged;
	}

	public KdbxMeta setSettingsChanged(final ZonedDateTime settingsChanged) {
		this.settingsChanged = settingsChanged;
		return this;
	}

	public String getDatabaseName() {
		return databaseName;
	}

	public KdbxMeta setDatabaseName(final String databaseName) {
		this.databaseName = databaseName;
		return this;
	}

	public ZonedDateTime getDatabaseNameChanged() {
		return databaseNameChanged;
	}

	public KdbxMeta setDatabaseNameChanged(final ZonedDateTime databaseNameChanged) {
		this.databaseNameChanged = databaseNameChanged;
		return this;
	}

	public String getDatabaseDescription() {
		return databaseDescription;
	}

	public KdbxMeta setDatabaseDescription(final String databaseDescription) {
		this.databaseDescription = databaseDescription;
		return this;
	}

	public ZonedDateTime getDatabaseDescriptionChanged() {
		return databaseDescriptionChanged;
	}

	public KdbxMeta setDatabaseDescriptionChanged(final ZonedDateTime databaseDescriptionChanged) {
		this.databaseDescriptionChanged = databaseDescriptionChanged;
		return this;
	}

	public String getDefaultUserName() {
		return defaultUserName;
	}

	public KdbxMeta setDefaultUserName(final String defaultUserName) {
		this.defaultUserName = defaultUserName;
		return this;
	}

	public ZonedDateTime getDefaultUserNameChanged() {
		return defaultUserNameChanged;
	}

	public KdbxMeta setDefaultUserNameChanged(final ZonedDateTime defaultUserNameChanged) {
		this.defaultUserNameChanged = defaultUserNameChanged;
		return this;
	}

	public String getMaintenanceHistoryDays() {
		return maintenanceHistoryDays;
	}

	public KdbxMeta setMaintenanceHistoryDays(final String maintenanceHistoryDays) {
		this.maintenanceHistoryDays = maintenanceHistoryDays;
		return this;
	}

	public String getColor() {
		return color;
	}

	public KdbxMeta setColor(final String color) {
		this.color = color;
		return this;
	}

	public ZonedDateTime getMasterKeyChanged() {
		return masterKeyChanged;
	}

	public KdbxMeta setMasterKeyChanged(final ZonedDateTime masterKeyChanged) {
		this.masterKeyChanged = masterKeyChanged;
		return this;
	}

	public String getMasterKeyChangeRec() {
		return masterKeyChangeRec;
	}

	public KdbxMeta setMasterKeyChangeRec(final String masterKeyChangeRec) {
		this.masterKeyChangeRec = masterKeyChangeRec;
		return this;
	}

	public String getMasterKeyChangeForce() {
		return masterKeyChangeForce;
	}

	public KdbxMeta setMasterKeyChangeForce(final String masterKeyChangeForce) {
		this.masterKeyChangeForce = masterKeyChangeForce;
		return this;
	}

	public String getRecycleBinEnabled() {
		return recycleBinEnabled;
	}

	public KdbxMeta setRecycleBinEnabled(final String recycleBinEnabled) {
		this.recycleBinEnabled = recycleBinEnabled;
		return this;
	}

	public String getRecycleBinUUID() {
		return recycleBinUUID;
	}

	public KdbxMeta setRecycleBinUUID(final String recycleBinUUID) {
		this.recycleBinUUID = recycleBinUUID;
		return this;
	}

	public ZonedDateTime getRecycleBinChanged() {
		return recycleBinChanged;
	}

	public KdbxMeta setRecycleBinChanged(final ZonedDateTime recycleBinChanged) {
		this.recycleBinChanged = recycleBinChanged;
		return this;
	}

	public String getEntryTemplatesGroup() {
		return entryTemplatesGroup;
	}

	public KdbxMeta setEntryTemplatesGroup(final String entryTemplatesGroup) {
		this.entryTemplatesGroup = entryTemplatesGroup;
		return this;
	}

	public ZonedDateTime getEntryTemplatesGroupChanged() {
		return entryTemplatesGroupChanged;
	}

	public KdbxMeta setEntryTemplatesGroupChanged(final ZonedDateTime entryTemplatesGroupChanged) {
		this.entryTemplatesGroupChanged = entryTemplatesGroupChanged;
		return this;
	}

	public String getHistoryMaxItems() {
		return historyMaxItems;
	}

	public KdbxMeta setHistoryMaxItems(final String historyMaxItems) {
		this.historyMaxItems = historyMaxItems;
		return this;
	}

	public String getHistoryMaxSize() {
		return historyMaxSize;
	}

	public KdbxMeta setHistoryMaxSize(final String historyMaxSize) {
		this.historyMaxSize = historyMaxSize;
		return this;
	}

	public String getLastSelectedGroup() {
		return lastSelectedGroup;
	}

	public KdbxMeta setLastSelectedGroup(final String lastSelectedGroup) {
		this.lastSelectedGroup = lastSelectedGroup;
		return this;
	}

	public String getLastTopVisibleGroup() {
		return lastTopVisibleGroup;
	}

	public KdbxMeta setLastTopVisibleGroup(final String lastTopVisibleGroup) {
		this.lastTopVisibleGroup = lastTopVisibleGroup;
		return this;
	}

	public String getBinaries() {
		return binaries;
	}

	public KdbxMeta setBinaries(final String binaries) {
		this.binaries = binaries;
		return this;
	}

	public KdbxMemoryProtection getMemoryProtection() {
		return memoryProtection;
	}

	public KdbxMeta setMemoryProtection(final KdbxMemoryProtection memoryProtection) {
		this.memoryProtection = memoryProtection;
		return this;
	}

	public List<KdbxCustomDataItem> getCustomData() {
		return customData;
	}

	public KdbxMeta setCustomData(final List<KdbxCustomDataItem> customData) {
		this.customData = customData;
		return this;
	}
}
