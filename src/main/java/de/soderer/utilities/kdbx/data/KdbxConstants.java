package de.soderer.utilities.kdbx.data;

import java.util.Arrays;

import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * Constants and identifiers of the KDBX file format.
 */
public class KdbxConstants {
	/**
	 * Magic number at the start of all KeePass database files (signature 1).
	 */
	public static final int KDBX_MAGICNUMBER = 0x9AA2D903;

	/**
	 * Utility class, not to be instantiated.
	 */
	private KdbxConstants() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * File type identifier (signature 2) of KeePass database files.
	 */
	public enum KdbxVersion {
		/**
		 * KeePass 1.x database (KDB format), not supported.
		 */
		KEEPASS1(0xB54BFB65, false),
		/**
		 * KeePass 2.x pre-release database.
		 */
		KEEPASS2_PRERELEASE(0xB54BFB66, true),
		/**
		 * KeePass 2.x database (KDBX format).
		 */
		KEEPASS2(0xB54BFB67, true);

		/**
		 * Signature value in the file.
		 */
		private final int versionId;
		/**
		 * Whether this is a KeePass 2.x (KDBX) file type.
		 */
		private final boolean isKeepass2;

		/**
		 * Returns the signature value in the file.
		 *
		 * @return the signature value
		 */
		public int getVersionId() {
			return versionId;
		}

		/**
		 * Returns whether this is a KeePass 2.x (KDBX) file type.
		 *
		 * @return true for KeePass 2.x file types
		 */
		public boolean isKeepass2() {
			return isKeepass2;
		}

		/**
		 * Creates the constant.
		 *
		 * @param versionId signature value in the file
		 * @param isKeepass2 whether this is a KeePass 2.x (KDBX) file type
		 */
		KdbxVersion(final int versionId, final boolean isKeepass2) {
			this.versionId = versionId;
			this.isKeepass2 = isKeepass2;
		}

		/**
		 * Returns the file type for a signature value.
		 *
		 * @param versionId signature value in the file
		 * @return the file type
		 * @throws Exception if the value is unknown
		 */
		public static KdbxVersion getById(final int versionId) throws Exception {
			for (final KdbxVersion version : KdbxVersion.values()) {
				if (version.getVersionId() == versionId) {
					return version;
				}
			}
			throw new Exception("Invalid version id: " + "0x" + Integer.toHexString(versionId));
		}
	}

	/**
	 * Key derivation functions identified by their UUID.
	 */
	public enum KeyDerivationFunction {
		/**
		 * AES-KDF as used in KDBX 3.x (transform rounds and seed in the outer header).
		 */
		AES_KDBX3(Utilities.fromHexString("c9d9f39a-628a-4460-bf74-0d08c18a4fea", true)),
		/**
		 * AES-KDF as used in KDBX 4.x (parameters in the KDF parameters dictionary).
		 */
		AES_KDBX4(Utilities.fromHexString("7c02bb82-79a7-4ac0-927d-114a00648238", true)),
		/**
		 * Argon2d (KDBX 4.x).
		 */
		ARGON2D(Utilities.fromHexString("ef636ddf-8c29-444b-91f7-a9a403e30a0c", true)),
		/**
		 * Argon2id (KDBX 4.x).
		 */
		ARGON2ID(Utilities.fromHexString("9e298b19-56db-4773-b23d-fc3ec6f0a1e6", true));

		/**
		 * UUID bytes identifying the key derivation function.
		 */
		private final byte[] id;

		/**
		 * Returns the UUID bytes identifying the key derivation function.
		 *
		 * @return the UUID bytes
		 */
		public byte[] getId() {
			return id;
		}

		/**
		 * Creates the constant.
		 *
		 * @param id UUID bytes identifying the key derivation function
		 */
		KeyDerivationFunction(final byte[] id) {
			this.id = id;
		}

		/**
		 * Returns the key derivation function for its UUID bytes.
		 *
		 * @param id UUID bytes
		 * @return the key derivation function
		 * @throws Exception if the id is unknown
		 */
		public static KeyDerivationFunction getById(final byte[] id) throws Exception {
			for (final KeyDerivationFunction keyDerivationFunction : KeyDerivationFunction.values()) {
				if (Arrays.equals(keyDerivationFunction.id, id)) {
					return keyDerivationFunction;
				}
			}
			throw new Exception("Invalid KeyDerivationFunction id: " + Utilities.toHexString(id));
		}
	}

	/**
	 * Ciphers for the encryption of the database payload, identified by their UUID.
	 */
	public enum OuterEncryptionAlgorithm {
		/**
		 * AES with 128 bit key (not supported by KeePass for writing).
		 */
		AES_128(Utilities.fromHexString("61ab05a1-9464-41c3-8d74-3a563df8dd35", true)),
		/**
		 * AES with 256 bit key in CBC mode.
		 */
		AES_256(Utilities.fromHexString("31c1f2e6-bf71-4350-be58-05216afc5aff", true)),
		/**
		 * ChaCha20 stream cipher (KDBX 4.x only).
		 */
		CHACHA20(Utilities.fromHexString("d6038a2b-8b6f-4cb5-a524-339a31dbb59a", true)),
		/**
		 * Twofish (KeePass plugin, not supported).
		 */
		TWOFISH(Utilities.fromHexString("ad68f29f-576f-4bb9-a36a-d47af965346c", true));

		/**
		 * UUID bytes identifying the cipher.
		 */
		private final byte[] id;

		/**
		 * Returns the UUID bytes identifying the cipher.
		 *
		 * @return the UUID bytes
		 */
		public byte[] getId() {
			return id;
		}

		/**
		 * Creates the constant.
		 *
		 * @param id UUID bytes identifying the cipher
		 */
		OuterEncryptionAlgorithm(final byte[] id) {
			this.id = id;
		}

		/**
		 * Returns the cipher for its UUID bytes.
		 *
		 * @param id UUID bytes
		 * @return the cipher
		 * @throws Exception if the id is unknown
		 */
		public static OuterEncryptionAlgorithm getById(final byte[] id) throws Exception {
			for (final OuterEncryptionAlgorithm outerEncryptionAlgorithm : OuterEncryptionAlgorithm.values()) {
				if (Arrays.equals(outerEncryptionAlgorithm.id, id)) {
					return outerEncryptionAlgorithm;
				}
			}
			throw new Exception("Invalid OuterEncryptionAlgorithm id: " + Utilities.toHexString(id));
		}
	}

	/**
	 * Stream ciphers for the protection of values within the XML payload ("inner random stream").
	 */
	public enum InnerEncryptionAlgorithm {
		/**
		 * No protection of values.
		 */
		NONE(0),
		/**
		 * ArcFour variant (outdated, not supported).
		 */
		ARC4_VARIANT(1),
		/**
		 * Salsa20 (default in KDBX 3.x).
		 */
		SALSA20(2),
		/**
		 * ChaCha20 (default in KDBX 4.x).
		 */
		CHACHA20(3);

		/**
		 * Id of the stream cipher in the header.
		 */
		private final int id;

		/**
		 * Returns the id of the stream cipher in the header.
		 *
		 * @return the id
		 */
		public int getId() {
			return id;
		}

		/**
		 * Creates the constant.
		 *
		 * @param id id of the stream cipher in the header
		 */
		InnerEncryptionAlgorithm(final int id) {
			this.id = id;
		}

		/**
		 * Returns the stream cipher for its id.
		 *
		 * @param id id in the header
		 * @return the stream cipher
		 * @throws Exception if the id is unknown
		 */
		public static InnerEncryptionAlgorithm getById(final int id) throws Exception {
			for (final InnerEncryptionAlgorithm innerEncryptionAlgorithm : InnerEncryptionAlgorithm.values()) {
				if (innerEncryptionAlgorithm.id == id) {
					return innerEncryptionAlgorithm;
				}
			}
			throw new Exception("Invalid InnerEncryptionAlgorithm id: " + id);
		}
	}

	/**
	 * Former interpretation of the first value of KDBX 3.x payload blocks.
	 *
	 * @deprecated The first value of a KDBX 3.x payload block is the consecutive block index, not a block type. The end of the payload is marked by a block with data length 0.
	 */
	@Deprecated
	public enum PayloadBlockType {
		/**
		 * Value 0, which is the index of the first block.
		 */
		PAYLOAD(0x00),
		/**
		 * Value 1, which is the index of the second block, not the end of the payload.
		 */
		END_OF_PAYLOAD(0x01);

		/**
		 * Value in the payload block.
		 */
		private final int id;

		/**
		 * Creates the constant.
		 *
		 * @param id value in the payload block
		 */
		PayloadBlockType(final int id) {
			this.id = id;
		}

		/**
		 * Returns the value in the payload block.
		 *
		 * @return the value
		 */
		public int getId() {
			return id;
		}
	}

	/**
	 * Standard icons of KeePass, identified by their icon id.
	 */
	public enum KdbxStandardIcon {
		/**
		 * Standard icon 0: an icon representing a generic password or key.
		 */
		AN_ICON_REPRESENTING_A_GENERIC_PASSWORD_OR_KEY(0),
		/**
		 * Standard icon 1: an icon representing a network or networking.
		 */
		AN_ICON_REPRESENTING_A_NETWORK_OR_NETWORKING(1),
		/**
		 * Standard icon 2: an icon representing a warning.
		 */
		AN_ICON_REPRESENTING_A_WARNING(2),
		/**
		 * Standard icon 3: server.
		 */
		SERVER(3),
		/**
		 * Standard icon 4: clipboard or pinned notes.
		 */
		CLIPBOARD_OR_PINNED_NOTES(4),
		/**
		 * Standard icon 5: an icon representing language or communication.
		 */
		AN_ICON_REPRESENTING_LANGUAGE_OR_COMMUNICATION(5),
		/**
		 * Standard icon 6: set of blocks are packages.
		 */
		SET_OF_BLOCKS_ARE_PACKAGES(6),
		/**
		 * Standard icon 7: text editor.
		 */
		TEXT_EDITOR(7),
		/**
		 * Standard icon 8: an icon representing a network socket.
		 */
		AN_ICON_REPRESENTING_A_NETWORK_SOCKET(8),
		/**
		 * Standard icon 9: an icon representing a user's identity.
		 */
		AN_ICON_REPRESENTING_A_USERS_IDENTITY(9),
		/**
		 * Standard icon 10: address book.
		 */
		ADDRESS_BOOK(10),
		/**
		 * Standard icon 11: camera or pictures.
		 */
		CAMERA_OR_PICTURES(11),
		/**
		 * Standard icon 12: wireless network.
		 */
		WIRELESS_NETWORK(12),
		/**
		 * Standard icon 13: key ring or set of keys.
		 */
		KEY_RING_OR_SET_OF_KEYS(13),
		/**
		 * Standard icon 14: an icon representing electric power or energy.
		 */
		AN_ICON_REPRESENTING_ELECTRIC_POWER_OR_ENERGY(14),
		/**
		 * Standard icon 15: scanner.
		 */
		SCANNER(15),
		/**
		 * Standard icon 16: an icon representing browser favorites or bookmarks.
		 */
		AN_ICON_REPRESENTING_BROWSER_FAVORITES_OR_BOOKMARKS(16),
		/**
		 * Standard icon 17: optical storage medium.
		 */
		OPTICAL_STORAGE_MEDIUM(17),
		/**
		 * Standard icon 18: monitor or display.
		 */
		MONITOR_OR_DISPLAY(18),
		/**
		 * Standard icon 19: email or letter.
		 */
		EMAIL_OR_LETTER(19),
		/**
		 * Standard icon 20: gears or icon representing configurable settings.
		 */
		GEARS_OR_ICON_REPRESENTING_CONFIGURABLE_SETTINGS(20),
		/**
		 * Standard icon 21: an icon representing a todo or check list.
		 */
		AN_ICON_REPRESENTING_A_TODO_OR_CHECK_LIST(21),
		/**
		 * Standard icon 22: empty text document.
		 */
		EMPTY_TEXT_DOCUMENT(22),
		/**
		 * Standard icon 23: computer desktop.
		 */
		COMPUTER_DESKTOP(23),
		/**
		 * Standard icon 24: an icon representing an established remote connection.
		 */
		AN_ICON_REPRESENTING_AN_ESTABLISHED_REMOTE_CONNECTION(24),
		/**
		 * Standard icon 25: email inbox.
		 */
		EMAIL_INBOX(25),
		/**
		 * Standard icon 26: floppy disk or save icon.
		 */
		FLOPPY_DISK_OR_SAVE_ICON(26),
		/**
		 * Standard icon 27: an icon representing remote storage.
		 */
		AN_ICON_REPRESENTING_REMOTE_STORAGE(27),
		/**
		 * Standard icon 28: an icon representing digital media files.
		 */
		AN_ICON_REPRESENTING_DIGITAL_MEDIA_FILES(28),
		/**
		 * Standard icon 29: an icon representing a secure shell.
		 */
		AN_ICON_REPRESENTING_A_SECURE_SHELL(29),
		/**
		 * Standard icon 30: console or terminal.
		 */
		CONSOLE_OR_TERMINAL(30),
		/**
		 * Standard icon 31: printer.
		 */
		PRINTER(31),
		/**
		 * Standard icon 32: an icon representing disk space utilization.
		 */
		AN_ICON_REPRESENTING_DISK_SPACE_UTILIZATION(32),
		/**
		 * Standard icon 33: an icon representing launching a program.
		 */
		AN_ICON_REPRESENTING_LAUNCHING_A_PROGRAM(33),
		/**
		 * Standard icon 34: wrench or icon representing configurable settings.
		 */
		WRENCH_OR_ICON_REPRESENTING_CONFIGURABLE_SETTINGS(34),
		/**
		 * Standard icon 35: an icon representing a computer connected to the internet.
		 */
		AN_ICON_REPRESENTING_A_COMPUTER_CONNECTED_TO_THE_INTERNET(35),
		/**
		 * Standard icon 36: an icon representing file compression.
		 */
		AN_ICON_REPRESENTING_FILE_COMPRESSION(36),
		/**
		 * Standard icon 37: an icon representing a percentage.
		 */
		AN_ICON_REPRESENTING_A_PERCENTAGE(37),
		/**
		 * Standard icon 38: an icon representing a windows file share.
		 */
		AN_ICON_REPRESENTING_A_WINDOWS_FILE_SHARE(38),
		/**
		 * Standard icon 39: an icon representing time.
		 */
		AN_ICON_REPRESENTING_TIME(39),
		/**
		 * Standard icon 40: magnifying glass or an icon representing search.
		 */
		MAGNIFYING_GLASS_OR_AN_ICON_REPRESENTING_SEARCH(40),
		/**
		 * Standard icon 41: splines or an icon representing vector graphics.
		 */
		SPLINES_OR_AN_ICON_REPRESENTING_VECTOR_GRAPHICS(41),
		/**
		 * Standard icon 42: memory hardware.
		 */
		MEMORY_HARDWARE(42),
		/**
		 * Standard icon 43: recycle bin.
		 */
		RECYCLE_BIN(43),
		/**
		 * Standard icon 44: post-it note.
		 */
		POSTIT_NOTE(44),
		/**
		 * Standard icon 45: red cross or icon representing canceling an action.
		 */
		RED_CROSS_OR_ICON_REPRESENTING_CANCELING_AN_ACTION(45),
		/**
		 * Standard icon 46: an icon representing usage help.
		 */
		AN_ICON_REPRESENTING_USAGE_HELP(46),
		/**
		 * Standard icon 47: software package.
		 */
		SOFTWARE_PACKAGE(47),
		/**
		 * Standard icon 48: closed folder.
		 */
		CLOSED_FOLDER(48),
		/**
		 * Standard icon 49: open folder.
		 */
		OPEN_FOLDER(49),
		/**
		 * Standard icon 50: tar archive.
		 */
		TAR_ARCHIVE(50),
		/**
		 * Standard icon 51: an icon representing decryption.
		 */
		AN_ICON_REPRESENTING_DECRYPTION(51),
		/**
		 * Standard icon 52: an icon representing encryption.
		 */
		AN_ICON_REPRESENTING_ENCRYPTION(52),
		/**
		 * Standard icon 53: green tick or an icon representing ok.
		 */
		GREEN_TICK_OR_AN_ICON_REPRESENTING_OK(53),
		/**
		 * Standard icon 54: pen or signature.
		 */
		PEN_OR_SIGNATURE(54),
		/**
		 * Standard icon 55: thumbnail image preview.
		 */
		THUMBNAIL_IMAGE_PREVIEW(55),
		/**
		 * Standard icon 56: address book alternative.
		 */
		ADDRESS_BOOK_ALTERNATIVE(56),
		/**
		 * Standard icon 57: an entry representing tabular data.
		 */
		AN_ENTRY_REPRESENTING_TABULAR_DATA(57),
		/**
		 * Standard icon 58: an icon representing a cryptographic private key.
		 */
		AN_ICON_REPRESENTING_A_CRYPTOGRAPHIC_PRIVATE_KEY(58),
		/**
		 * Standard icon 59: an icon representing software or package development.
		 */
		AN_ICON_REPRESENTING_SOFTWARE_OR_PACKAGE_DEVELOPMENT(59),
		/**
		 * Standard icon 60: an icon representing a user's home folder.
		 */
		AN_ICON_REPRESENTING_A_USERS_HOME_FOLDER(60),
		/**
		 * Standard icon 61: a star or an icon representing favorites.
		 */
		A_STAR_OR_AN_ICON_REPRESENTING_FAVORITES(61),
		/**
		 * Standard icon 62: tux penguin.
		 */
		TUX_PENGUIN(62),
		/**
		 * Standard icon 63: feather or an icon representing the apache web server.
		 */
		FEATHER_OR_AN_ICON_REPRESENTING_THE_APACHE_WEB_SERVER(63),
		/**
		 * Standard icon 64: apple or an icon representing macos.
		 */
		APPLE_OR_AN_ICON_REPRESENTING_MACOS(64),
		/**
		 * Standard icon 65: an icon representing wikipedia.
		 */
		AN_ICON_REPRESENTING_WIKIPEDIA(65),
		/**
		 * Standard icon 66: an icon representing money or finances.
		 */
		AN_ICON_REPRESENTING_MONEY_OR_FINANCES(66),
		/**
		 * Standard icon 67: an icon representing a digital certificate.
		 */
		AN_ICON_REPRESENTING_A_DIGITAL_CERTIFICATE(67),
		/**
		 * Standard icon 68: a mobile device.
		 */
		A_MOBILE_DEVICE(68);

		/**
		 * Icon id as stored in the database.
		 */
		private final int id;

		/**
		 * Creates the constant.
		 *
		 * @param id icon id as stored in the database
		 */
		KdbxStandardIcon(final int id) {
			this.id = id;
		}

		/**
		 * Returns the icon id as stored in the database.
		 *
		 * @return the icon id
		 */
		public int getId() {
			return id;
		}

		/**
		 * Returns the standard icon for its id.
		 *
		 * @param iconID icon id as stored in the database
		 * @return the standard icon
		 * @throws Exception if the id is unknown
		 */
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
