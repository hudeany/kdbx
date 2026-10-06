package de.soderer.utilities.kdbx.data;

import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Meta data of a KeePass database ("Meta" node of the XML payload): database name and settings, recycle bin, history limits and more.
 */
public class KdbxMeta {
	/**
	 * Name of the program, which created the KDBX file.
	 */
	private String generator;
	/**
	 * Base64 encoded SHA-256 hash of the KDBX 3.x header data, which is used to verify the integrity of the unencrypted header (not used in KDBX 4.x).
	 */
	private String headerHash;
	/**
	 * Time of the last change of settings or meta data.
	 */
	private ZonedDateTime settingsChanged;
	/**
	 * Name of the database.
	 */
	private String databaseName;
	/**
	 * Time of the last change of the database name.
	 */
	private ZonedDateTime databaseNameChanged;
	/**
	 * Description of the database.
	 */
	private String databaseDescription;
	/**
	 * Time of the last change of the database description.
	 */
	private ZonedDateTime databaseDescriptionChanged;
	/**
	 * Default user name for new entries.
	 */
	private String defaultUserName;
	/**
	 * Time of the last change of the default user name.
	 */
	private ZonedDateTime defaultUserNameChanged;
	/**
	 * Maximum age in days of history entries.
	 */
	private int maintenanceHistoryDays;
	/**
	 * Color for display of the database in the GUI, as HTML color text (e.g. "#FF0000").
	 */
	private String color;
	/**
	 * Time of the last master key change. It is only updated by the writer, when the credentials were changed.
	 */
	private ZonedDateTime masterKeyChanged;
	/**
	 * Master key age in days, after which a change is recommended (-1 for unlimited).
	 */
	private int masterKeyChangeRec;
	/**
	 * Master key age in days, after which a change is enforced (-1 for unlimited).
	 */
	private int masterKeyChangeForce;
	/**
	 * Whether a master key change is enforced on the next opening of the database.
	 */
	private boolean masterKeyChangeForceOnce;
	/**
	 * Whether the recycle bin is enabled.
	 */
	private boolean recycleBinEnabled;
	/**
	 * UUID of the recycle bin group.
	 */
	private KdbxUUID recycleBinUUID;
	/**
	 * Time of the last change of the recycle bin group.
	 */
	private ZonedDateTime recycleBinChanged;
	/**
	 * UUID of the group containing entry templates.
	 */
	private KdbxUUID entryTemplatesGroup;
	/**
	 * Time of the last change of the entry templates group.
	 */
	private ZonedDateTime entryTemplatesGroupChanged;
	/**
	 * Maximum number of history entries per entry (-1 for unlimited).
	 */
	private int historyMaxItems;
	/**
	 * Maximum size in bytes of the history of an entry (-1 for unlimited).
	 */
	private int historyMaxSize;
	/**
	 * UUID of the last selected group.
	 */
	private KdbxUUID lastSelectedGroup;
	/**
	 * UUID of the last group at the top of the visible group list.
	 */
	private KdbxUUID lastTopVisibleGroup;
	/**
	 * Settings, which standard fields of entries are written as protected values.
	 */
	private KdbxMemoryProtection memoryProtection;
	/**
	 * Custom data items of the database (key/value data of plugins and applications).
	 */
	private List<KdbxCustomDataItem> customData;
	/**
	 * Image data of custom icons by icon UUID.
	 */
	private Map<KdbxUUID, byte[]> customIcons = new LinkedHashMap<>();

	/**
	 * Creates meta data with default values.
	 */
	public KdbxMeta() {
		// nothing to do
	}

	/**
	 * Sets the name of the program, which created the KDBX file.
	 *
	 * @param generator the name of the program, which created the KDBX file
	 */
	public void setGenerator(final String generator) {
		this.generator = generator;
	}

	/**
	 * Sets the name of the program, which created the KDBX file and returns this object for method chaining.
	 *
	 * @param newGenerator the name of the program, which created the KDBX file
	 * @return this object
	 */
	public KdbxMeta withGenerator(final String newGenerator) {
		setGenerator(newGenerator);
		return this;
	}

	/**
	 * Returns the name of the program, which created the KDBX file.
	 *
	 * @return the name of the program, which created the KDBX file
	 */
	public String getGenerator() {
		return generator;
	}

	/**
	 * Sets the base64 encoded SHA-256 hash of the KDBX 3.x header data, which is used to verify the integrity of the unencrypted header (not used in KDBX 4.x).
	 *
	 * @param headerHash the base64 encoded SHA-256 hash of the KDBX 3.x header data, which is used to verify the integrity of the unencrypted header (not used in KDBX 4.x)
	 */
	public void setHeaderHash(final String headerHash) {
		this.headerHash = headerHash;
	}

	/**
	 * Sets the base64 encoded SHA-256 hash of the KDBX 3.x header data, which is used to verify the integrity of the unencrypted header (not used in KDBX 4.x) and returns this object for method chaining.
	 *
	 * @param newHeaderHash the base64 encoded SHA-256 hash of the KDBX 3.x header data, which is used to verify the integrity of the unencrypted header (not used in KDBX 4.x)
	 * @return this object
	 */
	public KdbxMeta withHeaderHash(final String newHeaderHash) {
		setHeaderHash(newHeaderHash);
		return this;
	}

	/**
	 * Returns the base64 encoded SHA-256 hash of the KDBX 3.x header data, which is used to verify the integrity of the unencrypted header (not used in KDBX 4.x).
	 *
	 * @return the base64 encoded SHA-256 hash of the KDBX 3.x header data, which is used to verify the integrity of the unencrypted header (not used in KDBX 4.x)
	 */
	public String getHeaderHash() {
		return headerHash;
	}

	/**
	 * Sets the time of the last change of settings or meta data.
	 *
	 * @param settingsChanged the time of the last change of settings or meta data
	 */
	public void setSettingsChanged(final ZonedDateTime settingsChanged) {
		this.settingsChanged = settingsChanged;
	}

	/**
	 * Sets the time of the last change of settings or meta data and returns this object for method chaining.
	 *
	 * @param newSettingsChanged the time of the last change of settings or meta data
	 * @return this object
	 */
	public KdbxMeta withSettingsChanged(final ZonedDateTime newSettingsChanged) {
		setSettingsChanged(newSettingsChanged);
		return this;
	}

	/**
	 * Returns the time of the last change of settings or meta data.
	 *
	 * @return the time of the last change of settings or meta data
	 */
	public ZonedDateTime getSettingsChanged() {
		return settingsChanged;
	}

	/**
	 * Sets the name of the database.
	 *
	 * @param databaseName the name of the database
	 */
	public void setDatabaseName(final String databaseName) {
		this.databaseName = databaseName;
	}

	/**
	 * Sets the name of the database and returns this object for method chaining.
	 *
	 * @param newDatabaseName the name of the database
	 * @return this object
	 */
	public KdbxMeta withDatabaseName(final String newDatabaseName) {
		setDatabaseName(newDatabaseName);
		return this;
	}

	/**
	 * Returns the name of the database.
	 *
	 * @return the name of the database
	 */
	public String getDatabaseName() {
		return databaseName;
	}

	/**
	 * Sets the time of the last change of the database name.
	 *
	 * @param databaseNameChanged the time of the last change of the database name
	 */
	public void setDatabaseNameChanged(final ZonedDateTime databaseNameChanged) {
		this.databaseNameChanged = databaseNameChanged;
	}

	/**
	 * Sets the time of the last change of the database name and returns this object for method chaining.
	 *
	 * @param newDatabaseNameChanged the time of the last change of the database name
	 * @return this object
	 */
	public KdbxMeta withDatabaseNameChanged(final ZonedDateTime newDatabaseNameChanged) {
		setDatabaseNameChanged(newDatabaseNameChanged);
		return this;
	}

	/**
	 * Returns the time of the last change of the database name.
	 *
	 * @return the time of the last change of the database name
	 */
	public ZonedDateTime getDatabaseNameChanged() {
		return databaseNameChanged;
	}

	/**
	 * Sets the description of the database.
	 *
	 * @param databaseDescription the description of the database
	 */
	public void setDatabaseDescription(final String databaseDescription) {
		this.databaseDescription = databaseDescription;
	}

	/**
	 * Sets the description of the database and returns this object for method chaining.
	 *
	 * @param newDatabaseDescription the description of the database
	 * @return this object
	 */
	public KdbxMeta withDatabaseDescription(final String newDatabaseDescription) {
		setDatabaseDescription(newDatabaseDescription);
		return this;
	}

	/**
	 * Returns the description of the database.
	 *
	 * @return the description of the database
	 */
	public String getDatabaseDescription() {
		return databaseDescription;
	}

	/**
	 * Sets the time of the last change of the database description.
	 *
	 * @param databaseDescriptionChanged the time of the last change of the database description
	 */
	public void setDatabaseDescriptionChanged(final ZonedDateTime databaseDescriptionChanged) {
		this.databaseDescriptionChanged = databaseDescriptionChanged;
	}

	/**
	 * Sets the time of the last change of the database description and returns this object for method chaining.
	 *
	 * @param newDatabaseDescriptionChanged the time of the last change of the database description
	 * @return this object
	 */
	public KdbxMeta withDatabaseDescriptionChanged(final ZonedDateTime newDatabaseDescriptionChanged) {
		setDatabaseDescriptionChanged(newDatabaseDescriptionChanged);
		return this;
	}

	/**
	 * Returns the time of the last change of the database description.
	 *
	 * @return the time of the last change of the database description
	 */
	public ZonedDateTime getDatabaseDescriptionChanged() {
		return databaseDescriptionChanged;
	}

	/**
	 * Sets the default user name for new entries.
	 *
	 * @param defaultUserName the default user name for new entries
	 */
	public void setDefaultUserName(final String defaultUserName) {
		this.defaultUserName = defaultUserName;
	}

	/**
	 * Sets the default user name for new entries and returns this object for method chaining.
	 *
	 * @param newDefaultUserName the default user name for new entries
	 * @return this object
	 */
	public KdbxMeta withDefaultUserName(final String newDefaultUserName) {
		setDefaultUserName(newDefaultUserName);
		return this;
	}

	/**
	 * Returns the default user name for new entries.
	 *
	 * @return the default user name for new entries
	 */
	public String getDefaultUserName() {
		return defaultUserName;
	}

	/**
	 * Sets the time of the last change of the default user name.
	 *
	 * @param defaultUserNameChanged the time of the last change of the default user name
	 */
	public void setDefaultUserNameChanged(final ZonedDateTime defaultUserNameChanged) {
		this.defaultUserNameChanged = defaultUserNameChanged;
	}

	/**
	 * Sets the time of the last change of the default user name and returns this object for method chaining.
	 *
	 * @param newDefaultUserNameChanged the time of the last change of the default user name
	 * @return this object
	 */
	public KdbxMeta withDefaultUserNameChanged(final ZonedDateTime newDefaultUserNameChanged) {
		setDefaultUserNameChanged(newDefaultUserNameChanged);
		return this;
	}

	/**
	 * Returns the time of the last change of the default user name.
	 *
	 * @return the time of the last change of the default user name
	 */
	public ZonedDateTime getDefaultUserNameChanged() {
		return defaultUserNameChanged;
	}

	/**
	 * Sets the maximum age in days of history entries.
	 *
	 * @param maintenanceHistoryDays the maximum age in days of history entries
	 */
	public void setMaintenanceHistoryDays(final int maintenanceHistoryDays) {
		this.maintenanceHistoryDays = maintenanceHistoryDays;
	}

	/**
	 * Sets the maximum age in days of history entries and returns this object for method chaining.
	 *
	 * @param newMaintenanceHistoryDays the maximum age in days of history entries
	 * @return this object
	 */
	public KdbxMeta withMaintenanceHistoryDays(final int newMaintenanceHistoryDays) {
		setMaintenanceHistoryDays(newMaintenanceHistoryDays);
		return this;
	}

	/**
	 * Returns the maximum age in days of history entries.
	 *
	 * @return the maximum age in days of history entries
	 */
	public int getMaintenanceHistoryDays() {
		return maintenanceHistoryDays;
	}

	/**
	 * Sets the color for display of the database in the GUI, as HTML color text (e.g. "#FF0000").
	 *
	 * @param color the color for display of the database in the GUI, as HTML color text (e.g. "#FF0000")
	 */
	public void setColor(final String color) {
		this.color = color;
	}

	/**
	 * Sets the color for display of the database in the GUI, as HTML color text (e.g. "#FF0000") and returns this object for method chaining.
	 *
	 * @param newColor the color for display of the database in the GUI, as HTML color text (e.g. "#FF0000")
	 * @return this object
	 */
	public KdbxMeta withColor(final String newColor) {
		setColor(newColor);
		return this;
	}

	/**
	 * Returns the color for display of the database in the GUI, as HTML color text (e.g. "#FF0000").
	 *
	 * @return the color for display of the database in the GUI, as HTML color text (e.g. "#FF0000")
	 */
	public String getColor() {
		return color;
	}

	/**
	 * Sets the time of the last master key change. It is only updated by the writer, when the credentials were changed.
	 *
	 * @param masterKeyChanged the time of the last master key change. It is only updated by the writer, when the credentials were changed
	 */
	public void setMasterKeyChanged(final ZonedDateTime masterKeyChanged) {
		this.masterKeyChanged = masterKeyChanged;
	}

	/**
	 * Sets the time of the last master key change. It is only updated by the writer, when the credentials were changed and returns this object for method chaining.
	 *
	 * @param newMasterKeyChanged the time of the last master key change. It is only updated by the writer, when the credentials were changed
	 * @return this object
	 */
	public KdbxMeta withMasterKeyChanged(final ZonedDateTime newMasterKeyChanged) {
		setMasterKeyChanged(newMasterKeyChanged);
		return this;
	}

	/**
	 * Returns the time of the last master key change. It is only updated by the writer, when the credentials were changed.
	 *
	 * @return the time of the last master key change. It is only updated by the writer, when the credentials were changed
	 */
	public ZonedDateTime getMasterKeyChanged() {
		return masterKeyChanged;
	}

	/**
	 * Sets the master key age in days, after which a change is recommended (-1 for unlimited).
	 *
	 * @param masterKeyChangeRec the master key age in days, after which a change is recommended (-1 for unlimited)
	 */
	public void setMasterKeyChangeRec(final int masterKeyChangeRec) {
		this.masterKeyChangeRec = masterKeyChangeRec;
	}

	/**
	 * Sets the master key age in days, after which a change is recommended (-1 for unlimited) and returns this object for method chaining.
	 *
	 * @param newMasterKeyChangeRec the master key age in days, after which a change is recommended (-1 for unlimited)
	 * @return this object
	 */
	public KdbxMeta withMasterKeyChangeRec(final int newMasterKeyChangeRec) {
		setMasterKeyChangeRec(newMasterKeyChangeRec);
		return this;
	}

	/**
	 * Returns the master key age in days, after which a change is recommended (-1 for unlimited).
	 *
	 * @return the master key age in days, after which a change is recommended (-1 for unlimited)
	 */
	public int getMasterKeyChangeRec() {
		return masterKeyChangeRec;
	}

	/**
	 * Sets the master key age in days, after which a change is enforced (-1 for unlimited).
	 *
	 * @param masterKeyChangeForce the master key age in days, after which a change is enforced (-1 for unlimited)
	 */
	public void setMasterKeyChangeForce(final int masterKeyChangeForce) {
		this.masterKeyChangeForce = masterKeyChangeForce;
	}

	/**
	 * Sets the master key age in days, after which a change is enforced (-1 for unlimited) and returns this object for method chaining.
	 *
	 * @param newMasterKeyChangeForce the master key age in days, after which a change is enforced (-1 for unlimited)
	 * @return this object
	 */
	public KdbxMeta withMasterKeyChangeForce(final int newMasterKeyChangeForce) {
		setMasterKeyChangeForce(newMasterKeyChangeForce);
		return this;
	}

	/**
	 * Returns the master key age in days, after which a change is enforced (-1 for unlimited).
	 *
	 * @return the master key age in days, after which a change is enforced (-1 for unlimited)
	 */
	public int getMasterKeyChangeForce() {
		return masterKeyChangeForce;
	}

	/**
	 * Sets whether a master key change is enforced on the next opening of the database.
	 *
	 * @param masterKeyChangeForceOnce whether a master key change is enforced on the next opening of the database
	 */
	public void setMasterKeyChangeForceOnce(final boolean masterKeyChangeForceOnce) {
		this.masterKeyChangeForceOnce = masterKeyChangeForceOnce;
	}

	/**
	 * Sets whether a master key change is enforced on the next opening of the database and returns this object for method chaining.
	 *
	 * @param newMasterKeyChangeForceOnce whether a master key change is enforced on the next opening of the database
	 * @return this object
	 */
	public KdbxMeta withMasterKeyChangeForceOnce(final boolean newMasterKeyChangeForceOnce) {
		setMasterKeyChangeForceOnce(newMasterKeyChangeForceOnce);
		return this;
	}

	/**
	 * Returns whether a master key change is enforced on the next opening of the database.
	 *
	 * @return whether a master key change is enforced on the next opening of the database
	 */
	public boolean isMasterKeyChangeForceOnce() {
		return masterKeyChangeForceOnce;
	}

	/**
	 * Sets whether the recycle bin is enabled.
	 *
	 * @param recycleBinEnabled whether the recycle bin is enabled
	 */
	public void setRecycleBinEnabled(final boolean recycleBinEnabled) {
		this.recycleBinEnabled = recycleBinEnabled;
		if (recycleBinEnabled && recycleBinUUID == null) {
			recycleBinUUID = new KdbxUUID();
		}
	}

	/**
	 * Sets whether the recycle bin is enabled and returns this object for method chaining.
	 *
	 * @param newRecycleBinEnabled whether the recycle bin is enabled
	 * @return this object
	 */
	public KdbxMeta withRecycleBinEnabled(final boolean newRecycleBinEnabled) {
		setRecycleBinEnabled(newRecycleBinEnabled);
		return this;
	}

	/**
	 * Returns whether the recycle bin is enabled.
	 *
	 * @return whether the recycle bin is enabled
	 */
	public boolean isRecycleBinEnabled() {
		return recycleBinEnabled;
	}

	/**
	 * Sets the UUID of the recycle bin group.
	 *
	 * @param recycleBinUUID the UUID of the recycle bin group
	 */
	public void setRecycleBinUUID(final KdbxUUID recycleBinUUID) {
		this.recycleBinUUID = recycleBinUUID;
	}

	/**
	 * Sets the UUID of the recycle bin group and returns this object for method chaining.
	 *
	 * @param newRecycleBinUUID the UUID of the recycle bin group
	 * @return this object
	 */
	public KdbxMeta withRecycleBinUUID(final KdbxUUID newRecycleBinUUID) {
		setRecycleBinUUID(newRecycleBinUUID);
		return this;
	}

	/**
	 * Returns the UUID of the recycle bin group.
	 *
	 * @return the UUID of the recycle bin group
	 */
	public KdbxUUID getRecycleBinUUID() {
		return recycleBinUUID;
	}

	/**
	 * Sets the time of the last change of the recycle bin group.
	 *
	 * @param recycleBinChanged the time of the last change of the recycle bin group
	 */
	public void setRecycleBinChanged(final ZonedDateTime recycleBinChanged) {
		this.recycleBinChanged = recycleBinChanged;
	}

	/**
	 * Sets the time of the last change of the recycle bin group and returns this object for method chaining.
	 *
	 * @param newRecycleBinChanged the time of the last change of the recycle bin group
	 * @return this object
	 */
	public KdbxMeta withRecycleBinChanged(final ZonedDateTime newRecycleBinChanged) {
		setRecycleBinChanged(newRecycleBinChanged);
		return this;
	}

	/**
	 * Returns the time of the last change of the recycle bin group.
	 *
	 * @return the time of the last change of the recycle bin group
	 */
	public ZonedDateTime getRecycleBinChanged() {
		return recycleBinChanged;
	}

	/**
	 * Sets the UUID of the group containing entry templates.
	 *
	 * @param entryTemplatesGroup the UUID of the group containing entry templates
	 */
	public void setEntryTemplatesGroup(final KdbxUUID entryTemplatesGroup) {
		this.entryTemplatesGroup = entryTemplatesGroup;
	}

	/**
	 * Sets the UUID of the group containing entry templates and returns this object for method chaining.
	 *
	 * @param newEntryTemplatesGroup the UUID of the group containing entry templates
	 * @return this object
	 */
	public KdbxMeta withEntryTemplatesGroup(final KdbxUUID newEntryTemplatesGroup) {
		setEntryTemplatesGroup(newEntryTemplatesGroup);
		return this;
	}

	/**
	 * Returns the UUID of the group containing entry templates.
	 *
	 * @return the UUID of the group containing entry templates
	 */
	public KdbxUUID getEntryTemplatesGroup() {
		return entryTemplatesGroup;
	}

	/**
	 * Sets the time of the last change of the entry templates group.
	 *
	 * @param entryTemplatesGroupChanged the time of the last change of the entry templates group
	 */
	public void setEntryTemplatesGroupChanged(final ZonedDateTime entryTemplatesGroupChanged) {
		this.entryTemplatesGroupChanged = entryTemplatesGroupChanged;
	}

	/**
	 * Sets the time of the last change of the entry templates group and returns this object for method chaining.
	 *
	 * @param newEntryTemplatesGroupChanged the time of the last change of the entry templates group
	 * @return this object
	 */
	public KdbxMeta withEntryTemplatesGroupChanged(final ZonedDateTime newEntryTemplatesGroupChanged) {
		setEntryTemplatesGroupChanged(newEntryTemplatesGroupChanged);
		return this;
	}

	/**
	 * Returns the time of the last change of the entry templates group.
	 *
	 * @return the time of the last change of the entry templates group
	 */
	public ZonedDateTime getEntryTemplatesGroupChanged() {
		return entryTemplatesGroupChanged;
	}

	/**
	 * Sets the maximum number of history entries per entry (-1 for unlimited).
	 *
	 * @param historyMaxItems the maximum number of history entries per entry (-1 for unlimited)
	 */
	public void setHistoryMaxItems(final int historyMaxItems) {
		this.historyMaxItems = historyMaxItems;
	}

	/**
	 * Sets the maximum number of history entries per entry (-1 for unlimited) and returns this object for method chaining.
	 *
	 * @param newHistoryMaxItems the maximum number of history entries per entry (-1 for unlimited)
	 * @return this object
	 */
	public KdbxMeta withHistoryMaxItems(final int newHistoryMaxItems) {
		setHistoryMaxItems(newHistoryMaxItems);
		return this;
	}

	/**
	 * Returns the maximum number of history entries per entry (-1 for unlimited).
	 *
	 * @return the maximum number of history entries per entry (-1 for unlimited)
	 */
	public int getHistoryMaxItems() {
		return historyMaxItems;
	}

	/**
	 * Sets the maximum size in bytes of the history of an entry (-1 for unlimited).
	 *
	 * @param historyMaxSize the maximum size in bytes of the history of an entry (-1 for unlimited)
	 */
	public void setHistoryMaxSize(final int historyMaxSize) {
		this.historyMaxSize = historyMaxSize;
	}

	/**
	 * Sets the maximum size in bytes of the history of an entry (-1 for unlimited) and returns this object for method chaining.
	 *
	 * @param newHistoryMaxSize the maximum size in bytes of the history of an entry (-1 for unlimited)
	 * @return this object
	 */
	public KdbxMeta withHistoryMaxSize(final int newHistoryMaxSize) {
		setHistoryMaxSize(newHistoryMaxSize);
		return this;
	}

	/**
	 * Returns the maximum size in bytes of the history of an entry (-1 for unlimited).
	 *
	 * @return the maximum size in bytes of the history of an entry (-1 for unlimited)
	 */
	public int getHistoryMaxSize() {
		return historyMaxSize;
	}

	/**
	 * Sets the UUID of the last selected group.
	 *
	 * @param lastSelectedGroup the UUID of the last selected group
	 */
	public void setLastSelectedGroup(final KdbxUUID lastSelectedGroup) {
		this.lastSelectedGroup = lastSelectedGroup;
	}

	/**
	 * Sets the UUID of the last selected group and returns this object for method chaining.
	 *
	 * @param newLastSelectedGroup the UUID of the last selected group
	 * @return this object
	 */
	public KdbxMeta withLastSelectedGroup(final KdbxUUID newLastSelectedGroup) {
		setLastSelectedGroup(newLastSelectedGroup);
		return this;
	}

	/**
	 * Returns the UUID of the last selected group.
	 *
	 * @return the UUID of the last selected group
	 */
	public KdbxUUID getLastSelectedGroup() {
		return lastSelectedGroup;
	}

	/**
	 * Sets the UUID of the last group at the top of the visible group list.
	 *
	 * @param lastTopVisibleGroup the UUID of the last group at the top of the visible group list
	 */
	public void setLastTopVisibleGroup(final KdbxUUID lastTopVisibleGroup) {
		this.lastTopVisibleGroup = lastTopVisibleGroup;
	}

	/**
	 * Sets the UUID of the last group at the top of the visible group list and returns this object for method chaining.
	 *
	 * @param newLastTopVisibleGroup the UUID of the last group at the top of the visible group list
	 * @return this object
	 */
	public KdbxMeta withLastTopVisibleGroup(final KdbxUUID newLastTopVisibleGroup) {
		setLastTopVisibleGroup(newLastTopVisibleGroup);
		return this;
	}

	/**
	 * Returns the UUID of the last group at the top of the visible group list.
	 *
	 * @return the UUID of the last group at the top of the visible group list
	 */
	public KdbxUUID getLastTopVisibleGroup() {
		return lastTopVisibleGroup;
	}

	/**
	 * Sets the settings, which standard fields of entries are written as protected values.
	 *
	 * @param memoryProtection the settings, which standard fields of entries are written as protected values
	 */
	public void setMemoryProtection(final KdbxMemoryProtection memoryProtection) {
		this.memoryProtection = memoryProtection;
	}

	/**
	 * Sets the settings, which standard fields of entries are written as protected values and returns this object for method chaining.
	 *
	 * @param newMemoryProtection the settings, which standard fields of entries are written as protected values
	 * @return this object
	 */
	public KdbxMeta withMemoryProtection(final KdbxMemoryProtection newMemoryProtection) {
		setMemoryProtection(newMemoryProtection);
		return this;
	}

	/**
	 * Returns the settings, which standard fields of entries are written as protected values.
	 *
	 * @return the settings, which standard fields of entries are written as protected values
	 */
	public KdbxMemoryProtection getMemoryProtection() {
		if (memoryProtection == null) {
			memoryProtection = new KdbxMemoryProtection();
		}
		return memoryProtection;
	}

	/**
	 * Sets the custom data items of the database (key/value data of plugins and applications).
	 *
	 * @param customData the custom data items of the database (key/value data of plugins and applications)
	 */
	public void setCustomData(final List<KdbxCustomDataItem> customData) {
		this.customData = customData;
	}

	/**
	 * Sets the custom data items of the database (key/value data of plugins and applications) and returns this object for method chaining.
	 *
	 * @param newCustomData the custom data items of the database (key/value data of plugins and applications)
	 * @return this object
	 */
	public KdbxMeta withCustomData(final List<KdbxCustomDataItem> newCustomData) {
		setCustomData(newCustomData);
		return this;
	}

	/**
	 * Returns the custom data items of the database (key/value data of plugins and applications).
	 *
	 * @return the custom data items of the database (key/value data of plugins and applications)
	 */
	public List<KdbxCustomDataItem> getCustomData() {
		return customData;
	}

	/**
	 * Sets the image data of custom icons by icon UUID.
	 *
	 * @param customIcons the image data of custom icons by icon UUID
	 */
	public void setCustomIcons(final Map<KdbxUUID, byte[]> customIcons) {
		this.customIcons = customIcons;
	}

	/**
	 * Sets the image data of custom icons by icon UUID and returns this object for method chaining.
	 *
	 * @param newCustomIcons the image data of custom icons by icon UUID
	 * @return this object
	 */
	public KdbxMeta withCustomIcons(final Map<KdbxUUID, byte[]> newCustomIcons) {
		setCustomIcons(newCustomIcons);
		return this;
	}

	/**
	 * Returns the image data of custom icons by icon UUID.
	 *
	 * @return the image data of custom icons by icon UUID
	 */
	public Map<KdbxUUID, byte[]> getCustomIcons() {
		return customIcons;
	}
}
