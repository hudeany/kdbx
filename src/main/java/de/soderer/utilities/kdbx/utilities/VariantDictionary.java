package de.soderer.utilities.kdbx.utilities;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

/**
 * Typed key/value dictionary of the KDBX 4.x format, used for the key derivation parameters and public custom data.
 */
public class VariantDictionary extends LinkedHashMap<String, VariantDictionaryEntry> {
	/**
	 * Serialization version.
	 */
	private static final long serialVersionUID = 267135612072510235L;

	/**
	 * Creates an empty dictionary.
	 */
	public VariantDictionary() {
		super();
	}

	/**
	 * Sanity upper bound for a single key or value entry, since VariantDictionary is used for small
	 * KDF parameters only. Protects against maliciously crafted length fields forcing huge allocations
	 * before any authentication of the file has taken place (Denial of Service protection).
	 */
	private static final int MAX_ENTRY_LENGTH = 1024 * 1024; // 1 MB

	/**
	 * Format version 1.0 as stored in the data (little endian 0x0100).
	 */
	public static final byte[] VERSION = new byte[] { 0x00, 0x01 };

	// Holds the UUID of the KeyDerivationFunction (KDF) algorithm
	/**
	 * Key of the UUID of the key derivation function.
	 */
	public static final String KDF_UUID = "$UUID";

	// AES params
	/**
	 * Key of the AES-KDF transform rounds.
	 */
	public static final String KDF_AES_ROUNDS = "R";
	/**
	 * Key of the AES-KDF transform seed.
	 */
	public static final String KDF_AES_SEED = "S";

	// Argon2 KDF parameters
	/**
	 * Key of the Argon2 salt.
	 */
	public static final String KDF_ARGON2_SALT = "S";
	/**
	 * Key of the Argon2 parallelism.
	 */
	public static final String KDF_ARGON2_PARALLELISM = "P";
	/**
	 * Key of the Argon2 memory size in bytes.
	 */
	public static final String KDF_ARGON2_MEMORY_IN_BYTES = "M";
	/**
	 * Key of the Argon2 iterations.
	 */
	public static final String KDF_ARGON2_ITERATIONS = "I";
	/**
	 * Key of the Argon2 version.
	 */
	public static final String KDF_ARGON2_VERSION = "V";

	/**
	 * Adds an entry from a Java value.
	 *
	 * @param key key of the entry
	 * @param type type of the entry
	 * @param value Java value matching the type
	 */
	public void put(final String key, final VariantDictionaryEntry.Type type, final Object value) {
		final VariantDictionaryEntry entry = new VariantDictionaryEntry(type, new byte[0]);
		entry.setJavaValue(value);
		super.put(key, entry);
	}

	/**
	 * Writes the dictionary in its binary format.
	 *
	 * @param outputStream the stream
	 * @throws Exception if writing fails
	 */
	public void write(final OutputStream outputStream) throws Exception {
		outputStream.write(VERSION);

		for (final Entry<String, VariantDictionaryEntry> entry : entrySet()) {
			outputStream.write(entry.getValue().getType().getId());

			final byte[] keyBytes = entry.getKey().getBytes(StandardCharsets.UTF_8);
			outputStream.write(Utilities.getLittleEndianBytes(keyBytes.length));
			outputStream.write(keyBytes);

			final byte[] dataBytes = entry.getValue().getValue();
			outputStream.write(Utilities.getLittleEndianBytes(dataBytes.length));
			outputStream.write(dataBytes);
		}

		outputStream.write(VariantDictionaryEntry.Type.END.getId());
	}

	/**
	 * Reads a dictionary from its binary format. Entries larger than 1 MB are rejected.
	 *
	 * @param inputStream the stream
	 * @return the dictionary
	 * @throws Exception if the data is invalid or of an unsupported major version
	 */
	public static VariantDictionary read(final InputStream inputStream) throws Exception {
		final byte[] versionBytes = Utilities.readFully(inputStream, 2, "VariantDictionary version bytes");
		// Like KeePass, only the major version (high byte of the little endian value) must match, newer minor versions are accepted
		if (versionBytes[1] != VERSION[1]) {
			throw new IOException("Unsupported VariantDictionary version " + Utilities.toHexString(versionBytes) + ", expected " + Utilities.toHexString(VERSION));
		}

		final VariantDictionary variantDictionary = new VariantDictionary();
		VariantDictionaryEntry.Type type;
		while ((type = VariantDictionaryEntry.Type.fromTypeId(inputStream.read())) != VariantDictionaryEntry.Type.END) {
			final int keyLen = Utilities.readLittleEndianIntFromStream(inputStream);
			checkLength(keyLen, "key");
			final byte[] keyByteBuffer = Utilities.readFully(inputStream, keyLen, "VariantDictionary key data");
			final String key = new String(keyByteBuffer, StandardCharsets.UTF_8);

			final int valueLen = Utilities.readLittleEndianIntFromStream(inputStream);
			checkLength(valueLen, "value");
			final byte[] valueByteBuffer = Utilities.readFully(inputStream, valueLen, "VariantDictionary value data");

			variantDictionary.put(key, new VariantDictionaryEntry(type, valueByteBuffer));
		}
		return variantDictionary;
	}

	/**
	 * Checks the length of a key or value.
	 *
	 * @param length the length
	 * @param fieldName name of the field for the error message
	 * @throws IOException for negative or excessive lengths
	 */
	private static void checkLength(final int length, final String fieldName) throws IOException {
		if (length < 0) {
			throw new IOException("Invalid negative VariantDictionary " + fieldName + " length: " + length);
		} else if (length > MAX_ENTRY_LENGTH) {
			throw new IOException("VariantDictionary " + fieldName + " length " + length + " exceeds maximum allowed size of " + MAX_ENTRY_LENGTH + " bytes");
		}
	}

}
