package de.soderer.utilities.kdbx.data;

import java.util.Arrays;

import de.soderer.utilities.kdbx.util.Utilities;

public class KdbxConstants {
	public static final int KDBX_MAGICNUMBER = 0x9AA2D903;

	public enum KdbxVersion {
		KEEPASS1(0xB54BFB65, false),
		KEEPASS2_PRERELEASE(0xB54BFB66, true),
		KEEPASS2(0xB54BFB67, true);

		private final int versionId;
		private final boolean isKeepass2;

		public int getVersionId() {
			return versionId;
		}

		public boolean isKeepass2() {
			return isKeepass2;
		}

		KdbxVersion(final int versionId, final boolean isKeepass2) {
			this.versionId = versionId;
			this.isKeepass2 = isKeepass2;
		}

		public static KdbxVersion getById(final int versionId) throws Exception {
			for (final KdbxVersion version : KdbxVersion.values()) {
				if (version.getVersionId() == versionId) {
					return version;
				}
			}
			throw new Exception("Invalid version id: " + "0x" + Integer.toHexString(versionId));
		}
	}

	public enum KdbxOuterHeaderType {
		/** ID 0: END entry, no more header entries after this */
		END_OF_HEADER(0),

		/** ID 1: COMMENT */
		COMMENT(1),

		/** ID 2: CIPHERID, bData="31c1f2e6bf714350be5805216afc5aff" => outer encryption AES256, currently no others supported */
		CIPHER_ID(2),

		/** ID 3: COMPRESSIONFLAGS, LE DWORD. 0=payload not compressed, 1=payload compressed with GZip */
		COMPRESSION_FLAGS(3),

		/** ID 4: MASTERSEED, 32 BYTEs string. See further down for usage/purpose. Length MUST be checked */
		MASTER_SEED(4),

		/** ID 5: TRANSFORMSEED, variable length BYTE string. See further down for usage/purpose */
		TRANSFORM_SEED(5),

		/** ID 6: TRANSFORMROUNDS, LE QWORD. See further down for usage/purpose */
		TRANSFORM_ROUNDS(6),

		/** ID 7: ENCRYPTIONIV, variable length BYTE string. See further down for usage/purpose */
		ENCRYPTION_IV(7),

		/** ID 8: PROTECTEDSTREAMKEY, variable length BYTE string. See further down for usage/purpose */
		PROTECTED_STREAM_KEY(8),

		/** ID 9: STREAMSTARTBYTES, variable length BYTE string. See further down for usage/purpose */
		STREAM_START_BYTES(9),

		/** ID 10: INNERRANDOMSTREAMID, LE DWORD <br />
		 * Inner stream encryption type: <br />
		 * 0=>none <br />
		 * 1=>Arc4Variant <br />
		 * 2=>Salsa20 <br />
		 * This is actually a type ID identifying the stream cipher used to sensitive content inside the XML payload. */
		INNER_RANDOM_STREAM_ID(10),

		/** ID 11 */
		KDF_PARAMETERS(11),

		/** ID 12 */
		PUBLIC_CUSTOM_DATA_PARAMETERS(12);

		private final int id;

		KdbxOuterHeaderType(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		public static KdbxOuterHeaderType getById(final int id) throws Exception {
			for (final KdbxOuterHeaderType kdbxOuterHeaderType : KdbxOuterHeaderType.values()) {
				if (kdbxOuterHeaderType.getId() == id) {
					return kdbxOuterHeaderType;
				}
			}
			throw new Exception("Invalid id: " + Integer.toHexString(id));
		}
	}

	public enum KdbxInnerHeaderType {
		/** ID 0: END entry, no more header entries after this */
		END_OF_HEADER(0),

		/**
		 * ID 1: Inner random stream ID (this supersedes the inner random stream ID stored in the outer header of a KDBX 3.1 file).
		 */
		INNER_RANDOM_STREAM_ID(1),

		/**
		 * ID 2: Inner random stream key (this supersedes the inner random stream key stored in the outer header of a KDBX 3.1 file).
		 */
		INNER_RANDOM_STREAM_KEY(2),

		/**
		 * ID 3: Binary (entry attachment). D = F ‖ M, where F is one byte and M is the binary content (i.e. the actual entry attachment data).
		 * F stores flags for the binary; supported flags are:
		 * - 0x01: The user has turned on process memory protection for this binary.
		 * // TODO on decryp protected data
		 */
		BINARY_ATTACHMENT(3);

		private final int id;

		KdbxInnerHeaderType(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		public static KdbxInnerHeaderType getById(final int id) throws Exception {
			for (final KdbxInnerHeaderType innerHeaderType : KdbxInnerHeaderType.values()) {
				if (innerHeaderType.getId() == id) {
					return innerHeaderType;
				}
			}
			throw new Exception("Invalid id: " + Integer.toHexString(id));
		}
	}

	public enum KeyDerivationFunction {
		AES_KDBX3(Utilities.fromHexString("c9d9f39a-628a-4460-bf74-0d08c18a4fea", true)),
		AES_KDBX4(Utilities.fromHexString("7c02bb82-79a7-4ac0-927d-114a00648238", true)),
		ARGON2D(Utilities.fromHexString("ef636ddf-8c29-444b-91f7-a9a403e30a0c", true)),
		ARGON2ID(Utilities.fromHexString("9e298b19-56db-4773-b23d-fc3ec6f0a1e6", true));

		private final byte[] id;

		public byte[] getId() {
			return id;
		}

		KeyDerivationFunction(final byte[] id) {
			this.id = id;
		}

		public static KeyDerivationFunction getById(final byte[] id) throws Exception {
			for (final KeyDerivationFunction keyDerivationFunction : KeyDerivationFunction.values()) {
				if (Arrays.equals(keyDerivationFunction.id, id)) {
					return keyDerivationFunction;
				}
			}
			throw new Exception("Invalid KeyDerivationFunction id: " + Utilities.toHexString(id));
		}
	}

	public enum OuterEncryptionAlgorithm {
		AES_128(Utilities.fromHexString("61ab05a1-9464-41c3-8d74-3a563df8dd35", true)),
		AES_256(Utilities.fromHexString("31c1f2e6-bf71-4350-be58-05216afc5aff", true)),
		CHACHA20(Utilities.fromHexString("d6038a2b-8b6f-4cb5-a524-339a31dbb59a", true)),
		TWOFISH(Utilities.fromHexString("ad68f29f-576f-4bb9-a36a-d47af965346c", true));

		private final byte[] id;

		public byte[] getId() {
			return id;
		}

		OuterEncryptionAlgorithm(final byte[] id) {
			this.id = id;
		}

		public static OuterEncryptionAlgorithm getById(final byte[] id) throws Exception {
			for (final OuterEncryptionAlgorithm outerEncryptionAlgorithm : OuterEncryptionAlgorithm.values()) {
				if (Arrays.equals(outerEncryptionAlgorithm.id, id)) {
					return outerEncryptionAlgorithm;
				}
			}
			throw new Exception("Invalid OuterEncryptionAlgorithm id: " + Utilities.toHexString(id));
		}
	}

	public enum InnerEncryptionAlgorithm {
		NONE(0),
		ARC4_VARIANT(1),
		SALSA20(2),
		CHACHA20(3);

		private final int id;

		public int getId() {
			return id;
		}

		InnerEncryptionAlgorithm(final int id) {
			this.id = id;
		}

		public static InnerEncryptionAlgorithm getById(final int id) throws Exception {
			for (final InnerEncryptionAlgorithm innerEncryptionAlgorithm : InnerEncryptionAlgorithm.values()) {
				if (innerEncryptionAlgorithm.id == id) {
					return innerEncryptionAlgorithm;
				}
			}
			throw new Exception("Invalid InnerEncryptionAlgorithm id: " + id);
		}
	}

	public enum PayloadBlockType {
		PAYLOAD(0x00),
		END_OF_PAYLOAD(0x01);

		private final int id;

		PayloadBlockType(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}
	}

	public enum KdbxStandardIcon {
		AN_ICON_REPRESENTING_A_GENERIC_PASSWORD_OR_KEY(0),
		AN_ICON_REPRESENTING_A_NETWORK_OR_NETWORKING(1),
		AN_ICON_REPRESENTING_A_WARNING(2),
		SERVER(3),
		CLIPBOARD_OR_PINNED_NOTES(4),
		AN_ICON_REPRESENTING_LANGUAGE_OR_COMMUNICATION(5),
		SET_OF_BLOCKS_ARE_PACKAGES(6),
		TEXT_EDITOR(7),
		AN_ICON_REPRESENTING_A_NETWORK_SOCKET(8),
		AN_ICON_REPRESENTING_A_USERS_IDENTITY(9),
		ADDRESS_BOOK(10),
		CAMERA_OR_PICTURES(11),
		WIRELESS_NETWORK(12),
		KEY_RING_OR_SET_OF_KEYS(13),
		AN_ICON_REPRESENTING_ELECTRIC_POWER_OR_ENERGY(14),
		SCANNER(15),
		AN_ICON_REPRESENTING_BROWSER_FAVORITES_OR_BOOKMARKS(16),
		OPTICAL_STORAGE_MEDIUM(17),
		MONITOR_OR_DISPLAY(18),
		EMAIL_OR_LETTER(19),
		GEARS_OR_ICON_REPRESENTING_CONFIGURABLE_SETTINGS(20),
		AN_ICON_REPRESENTING_A_TODO_OR_CHECK_LIST(21),
		EMPTY_TEXT_DOCUMENT(22),
		COMPUTER_DESKTOP(23),
		AN_ICON_REPRESENTING_AN_ESTABLISHED_REMOTE_CONNECTION(24),
		EMAIL_INBOX(25),
		FLOPPY_DISK_OR_SAVE_ICON(26),
		AN_ICON_REPRESENTING_REMOTE_STORAGE(27),
		AN_ICON_REPRESENTING_DIGITAL_MEDIA_FILES(28),
		AN_ICON_REPRESENTING_A_SECURE_SHELL(29),
		CONSOLE_OR_TERMINAL(30),
		PRINTER(31),
		AN_ICON_REPRESENTING_DISK_SPACE_UTILIZATION(32),
		AN_ICON_REPRESENTING_LAUNCHING_A_PROGRAM(33),
		WRENCH_OR_ICON_REPRESENTING_CONFIGURABLE_SETTINGS(34),
		AN_ICON_REPRESENTING_A_COMPUTER_CONNECTED_TO_THE_INTERNET(35),
		AN_ICON_REPRESENTING_FILE_COMPRESSION(36),
		AN_ICON_REPRESENTING_A_PERCENTAGE(37),
		AN_ICON_REPRESENTING_A_WINDOWS_FILE_SHARE(38),
		AN_ICON_REPRESENTING_TIME(39),
		MAGNIFYING_GLASS_OR_AN_ICON_REPRESENTING_SEARCH(40),
		SPLINES_OR_AN_ICON_REPRESENTING_VECTOR_GRAPHICS(41),
		MEMORY_HARDWARE(42),
		RECYCLE_BIN(43),
		POSTIT_NOTE(44),
		RED_CROSS_OR_ICON_REPRESENTING_CANCELING_AN_ACTION(45),
		AN_ICON_REPRESENTING_USAGE_HELP(46),
		SOFTWARE_PACKAGE(47),
		CLOSED_FOLDER(48),
		OPEN_FOLDER(49),
		TAR_ARCHIVE(50),
		AN_ICON_REPRESENTING_DECRYPTION(51),
		AN_ICON_REPRESENTING_ENCRYPTION(52),
		GREEN_TICK_OR_AN_ICON_REPRESENTING_OK(53),
		PEN_OR_SIGNATURE(54),
		THUMBNAIL_IMAGE_PREVIEW(55),
		ADDRESS_BOOK_ALTERNATIVE(56),
		AN_ENTRY_REPRESENTING_TABULAR_DATA(57),
		AN_ICON_REPRESENTING_A_CRYPTOGRAPHIC_PRIVATE_KEY(58),
		AN_ICON_REPRESENTING_SOFTWARE_OR_PACKAGE_DEVELOPMENT(59),
		AN_ICON_REPRESENTING_A_USERS_HOME_FOLDER(60),
		A_STAR_OR_AN_ICON_REPRESENTING_FAVORITES(61),
		TUX_PENGUIN(62),
		FEATHER_OR_AN_ICON_REPRESENTING_THE_APACHE_WEB_SERVER(63),
		APPLE_OR_AN_ICON_REPRESENTING_MACOS(64),
		AN_ICON_REPRESENTING_WIKIPEDIA(65),
		AN_ICON_REPRESENTING_MONEY_OR_FINANCES(66),
		AN_ICON_REPRESENTING_A_DIGITAL_CERTIFICATE(67),
		A_MOBILE_DEVICE(68);

		private final int id;

		KdbxStandardIcon(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		public static KdbxStandardIcon getById(final int iconID) throws Exception {
			for (final KdbxStandardIcon version : KdbxStandardIcon.values()) {
				if (version.getId() == iconID) {
					return version;
				}
			}
			throw new Exception("Invalid standard icon id: " + Integer.toHexString(iconID));
		}
	}
}
