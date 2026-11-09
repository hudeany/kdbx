package de.soderer.utilities.kdbx;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import de.soderer.utilities.kdbx.utilities.Utilities;

/**
 * Credentials of a KDBX database: master password, key file and/or Windows user account.
 * <p>
 * Supported key file formats (detected in this order, like KeePass and KeePassXC do):
 * <ul>
 * <li>XML key file (version 1.0 with base64 key, version 2.0 with hexadecimal key and integrity hash), optionally with UTF-8 BOM</li>
 * <li>Exactly 32 bytes, used directly as 256-bit key</li>
 * <li>Exactly 64 hexadecimal characters (no line break), decoded to a 256-bit key</li>
 * <li>Any other content (also invalid XML), hashed with SHA-256</li>
 * </ul>
 */
public class KdbxCredentials {
	/**
	 * Master password or null.
	 */
	private char[] password = null;
	/**
	 * Content of the key file or null.
	 */
	private byte[] keyFileData = null;
	/**
	 * Unprotected Windows user account key (content of KeePass' "ProtectedUserKey.bin" after DPAPI decryption) or null.
	 *
	 * @see WindowsUserAccountKey
	 */
	private byte[] windowsUserAccountKey = null;

	/**
	 * Creates credentials with a master password only.
	 *
	 * @param password the master password
	 */
	public KdbxCredentials(final char[] password) {
		this.password = password;
	}

	/**
	 * Creates credentials with a key file only.
	 *
	 * @param keyFileData content of the key file
	 */
	public KdbxCredentials(final byte[] keyFileData) {
		this.keyFileData = keyFileData;
	}

	/**
	 * Creates credentials with master password and key file.
	 *
	 * @param password the master password or null
	 * @param keyFileData content of the key file or null
	 */
	public KdbxCredentials(final char[] password, final byte[] keyFileData) {
		this.password = password;
		this.keyFileData = keyFileData;
	}

	/**
	 * Creates credentials with master password, key file and Windows user account key.
	 * <p>
	 * The Windows user account key is the DPAPI-decrypted content of KeePass' "ProtectedUserKey.bin".
	 * Use {@link WindowsUserAccountKey#load()} to read it for the currently logged on Windows user.
	 *
	 * @param password the master password or null
	 * @param keyFileData content of the key file or null
	 * @param windowsUserAccountKey the unprotected Windows user account key or null
	 */
	public KdbxCredentials(final char[] password, final byte[] keyFileData, final byte[] windowsUserAccountKey) {
		this.password = password;
		this.keyFileData = keyFileData;
		this.windowsUserAccountKey = windowsUserAccountKey;
	}

	/**
	 * Adds the key of the currently logged on Windows user account (like KeePass' option "Windows user account").
	 * The key is read from "%APPDATA%\KeePass\ProtectedUserKey.bin" and decrypted via Windows DPAPI.
	 * Works on Windows only.
	 *
	 * @return this credentials object for chaining
	 * @throws Exception if the key cannot be read or decrypted
	 */
	public KdbxCredentials withCurrentWindowsUserAccount() throws Exception {
		windowsUserAccountKey = WindowsUserAccountKey.load();
		return this;
	}

	/**
	 * Sets the unprotected Windows user account key.
	 *
	 * @param newWindowsUserAccountKey the unprotected Windows user account key or null
	 * @return this credentials object for chaining
	 */
	public KdbxCredentials withWindowsUserAccountKey(final byte[] newWindowsUserAccountKey) {
		this.windowsUserAccountKey = newWindowsUserAccountKey;
		return this;
	}

	/**
	 * Creates the composite key hash: SHA-256 over the concatenation of SHA-256(password), the key file key
	 * and SHA-256(Windows user account key), in this order (same as KeePass).
	 *
	 * @return the 32 bytes composite key hash
	 * @throws Exception if the key file is invalid
	 */
	public byte[] createCompositeKeyHash() throws Exception {
		final ByteArrayOutputStream concat = new ByteArrayOutputStream();

		if (password != null) {
			final byte[] passwordBytes = Utilities.toBytes(password);
			try {
				final byte[] passwordHash = MessageDigest.getInstance("SHA-256").digest(passwordBytes);
				concat.write(passwordHash, 0, passwordHash.length);
			} finally {
				Arrays.fill(passwordBytes, (byte) 0); // clear sensitive data
			}
		}

		if (keyFileData != null) {
			final byte[] keyFileKey = getKeyFileKey(keyFileData);
			concat.write(keyFileKey, 0, keyFileKey.length);
		}

		if (windowsUserAccountKey != null) {
			// KeePass (KcpUserAccount) uses the SHA-256 hash of the unprotected user key
			final byte[] windowsUserAccountKeyHash = MessageDigest.getInstance("SHA-256").digest(windowsUserAccountKey);
			concat.write(windowsUserAccountKeyHash, 0, windowsUserAccountKeyHash.length);
			Arrays.fill(windowsUserAccountKeyHash, (byte) 0); // clear sensitive data
		}

		final byte[] compositeKeyBytes = concat.toByteArray();

		final byte[] compositeKeyHash = MessageDigest.getInstance("SHA-256").digest(compositeKeyBytes);
		Arrays.fill(compositeKeyBytes, (byte) 0); // clear sensitive data
		return compositeKeyHash;
	}

	/**
	 * Derives the key from key file data in the same order of format detection as KeePass and KeePassXC:
	 * XML key file, 32 raw bytes, exactly 64 hexadecimal characters, hash of any other file content.
	 *
	 * @param keyFileData content of the key file
	 * @return the key file key
	 * @throws Exception if an XML key file is invalid or corrupted
	 */
	private static byte[] getKeyFileKey(final byte[] keyFileData) throws Exception {
		final byte[] xmlKeyFileKey = getXmlKeyFileKey(keyFileData);
		if (xmlKeyFileKey != null) {
			return xmlKeyFileKey;
		} else if (keyFileData.length == 32) {
			// 32 raw bytes are used directly as a 256-bit cryptographic key
			return keyFileData;
		} else if (isHexKeyFileFormat(keyFileData)) {
			// Exactly 64 hexadecimal characters decode to a 256-bit cryptographic key
			return Utilities.fromHexString(new String(keyFileData, StandardCharsets.US_ASCII));
		} else {
			return MessageDigest.getInstance("SHA-256").digest(keyFileData);
		}
	}

	/**
	 * Reads the key of an XML key file.
	 * Data, which cannot be parsed as XML or has no "KeyFile" root element, is no XML key file.
	 *
	 * @param keyFileData content of the key file
	 * @return the key or null, if the data is not an XML key file
	 * @throws Exception if the XML key file has no key data, an unsupported version or a wrong integrity hash
	 */
	private static byte[] getXmlKeyFileKey(final byte[] keyFileData) throws Exception {
		byte[] xmlData = keyFileData;
		if (xmlData.length >= 3 && (xmlData[0] & 0xFF) == 0xEF && (xmlData[1] & 0xFF) == 0xBB && (xmlData[2] & 0xFF) == 0xBF) {
			// Skip UTF-8 BOM
			xmlData = Arrays.copyOfRange(xmlData, 3, xmlData.length);
		}
		if (!Utilities.isXmlDocument(xmlData)) {
			return null;
		}

		final Document document;
		try {
			document = Utilities.parseXmlFile(xmlData);
		} catch (@SuppressWarnings("unused") final Exception e) {
			// Not a valid XML document: KeePass uses the hash of the file content in this case
			return null;
		}
		final Element rootNode = document.getDocumentElement();
		if (rootNode == null || !"KeyFile".equals(rootNode.getNodeName())) {
			return null;
		}

		String version = null;
		final Node metaNode = Utilities.getChildNodesMap(rootNode).get("Meta");
		if (metaNode != null) {
			final Node versionNode = Utilities.getChildNodesMap(metaNode).get("Version");
			if (versionNode != null) {
				version = Utilities.getNodeValue(versionNode);
			}
		}
		if (version != null) {
			version = version.trim();
		}

		final Node keyNode = Utilities.getChildNodesMap(rootNode).get("Key");
		final Node dataNode = keyNode == null ? null : Utilities.getChildNodesMap(keyNode).get("Data");
		final String dataString = dataNode == null ? null : Utilities.getNodeValue(dataNode);
		if (dataString == null || Utilities.isBlank(dataString)) {
			throw new Exception("Invalid XML key file: Missing key data");
		}

		if (version != null && version.startsWith("1.")) {
			return Base64.getMimeDecoder().decode(dataString.trim());
		} else if (version != null && version.startsWith("2.")) {
			final byte[] keyBytes = Utilities.fromHexString(dataString, true);
			final String hashHexString = Utilities.getAttributeValue(dataNode, "Hash");
			if (Utilities.isNotBlank(hashHexString)) {
				// Version 2.0 contains the first 4 bytes of the SHA-256 hash of the key to detect corrupted key files
				final byte[] hashBytes = Utilities.fromHexString(hashHexString, true);
				final byte[] keyBytesHash = MessageDigest.getInstance("SHA-256").digest(keyBytes);
				if (hashBytes.length < 4 || !MessageDigest.isEqual(Arrays.copyOf(keyBytesHash, 4), Arrays.copyOf(hashBytes, 4))) {
					throw new Exception("Invalid XML key file: Key data hash does not match, the key file is corrupted");
				}
			}
			return keyBytes;
		} else {
			throw new Exception("Unsupported XML key file version: " + version);
		}
	}

	/**
	 * Detects the "64 hexadecimal characters" key file format: exactly 64 bytes, each a hexadecimal character (0-9, a-f, A-F).
	 * Like KeePass and KeePassXC, any other size (e.g. with a trailing line break) is not detected as hexadecimal key file and is hashed instead.
	 *
	 * @param keyFileData content of the key file
	 * @return true for the hexadecimal key file format
	 */
	private static boolean isHexKeyFileFormat(final byte[] keyFileData) {
		if (keyFileData.length != 64) {
			return false;
		}
		for (final byte keyFileByte : keyFileData) {
			if (Character.digit((char) (keyFileByte & 0xFF), 16) < 0) {
				return false;
			}
		}
		return true;
	}
}
