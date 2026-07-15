package de.soderer.utilities.kdbx.utilities;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

public class VariantDictionary extends LinkedHashMap<String, VariantDictionaryEntry> {
	private static final long serialVersionUID = 267135612072510235L;

	/**
	 * Sanity upper bound for a single key or value entry, since VariantDictionary is used for small
	 * KDF parameters only. Protects against maliciously crafted length fields forcing huge allocations
	 * before any authentication of the file has taken place (Denial of Service protection).
	 */
	private static final int MAX_ENTRY_LENGTH = 1024 * 1024; // 1 MB

	/**
	 * A little-endian system stores the least-significant byte at the smallest address.
	 */
	public static final byte[] VERSION = new byte[] { 0x00, 0x01 };

	// Holds the UUID of the KeyDerivationFunction (KDF) algorithm
	public static final String KDF_UUID = "$UUID";

	// AES params
	public static final String KDF_AES_ROUNDS = "R";
	public static final String KDF_AES_SEED = "S";

	// Argon2 KDF parameters
	public static final String KDF_ARGON2_SALT = "S";
	public static final String KDF_ARGON2_PARALLELISM = "P";
	public static final String KDF_ARGON2_MEMORY_IN_BYTES = "M";
	public static final String KDF_ARGON2_ITERATIONS = "I";
	public static final String KDF_ARGON2_VERSION = "V";

	public void put(final String key, final VariantDictionaryEntry.Type type, final Object value) {
		final VariantDictionaryEntry entry = new VariantDictionaryEntry(type, new byte[0]);
		entry.setJavaValue(value);
		super.put(key, entry);
	}

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

	public static VariantDictionary read(final InputStream inputStream) throws Exception {
		final byte[] versionBytes = new byte[2];
		readFully(inputStream, versionBytes, "VariantDictionary version bytes");
		if (!Arrays.equals(versionBytes, VERSION)) {
			throw new IOException("Unsupported VariantDictionary version " + Utilities.toHexString(versionBytes) + ", expected " + Utilities.toHexString(VERSION));
		}

		final VariantDictionary variantDictionary = new VariantDictionary();
		VariantDictionaryEntry.Type type;
		while ((type = VariantDictionaryEntry.Type.fromTypeId(inputStream.read())) != VariantDictionaryEntry.Type.END) {
			final int keyLen = Utilities.readLittleEndianIntFromStream(inputStream);
			checkLength(keyLen, "key");
			final byte[] keyByteBuffer = new byte[keyLen];
			readFully(inputStream, keyByteBuffer, "VariantDictionary key data");
			final String key = new String(keyByteBuffer, StandardCharsets.UTF_8);

			final int valueLen = Utilities.readLittleEndianIntFromStream(inputStream);
			checkLength(valueLen, "value");
			final byte[] valueByteBuffer = new byte[valueLen];
			readFully(inputStream, valueByteBuffer, "VariantDictionary value data");

			variantDictionary.put(key, new VariantDictionaryEntry(type, valueByteBuffer));
		}
		return variantDictionary;
	}

	private static void checkLength(final int length, final String fieldName) throws IOException {
		if (length < 0) {
			throw new IOException("Invalid negative VariantDictionary " + fieldName + " length: " + length);
		} else if (length > MAX_ENTRY_LENGTH) {
			throw new IOException("VariantDictionary " + fieldName + " length " + length + " exceeds maximum allowed size of " + MAX_ENTRY_LENGTH + " bytes");
		}
	}

	/**
	 * Read exactly data.length bytes, looping over the underlying stream as needed, since a single
	 * InputStream#read(byte[]) call is not guaranteed to fill the buffer even before EOF is reached.
	 */
	private static void readFully(final InputStream inputStream, final byte[] data, final String description) throws IOException {
		int totalBytesRead = 0;
		while (totalBytesRead < data.length) {
			final int bytesRead = inputStream.read(data, totalBytesRead, data.length - totalBytesRead);
			if (bytesRead < 0) {
				throw new EOFException("Cannot read " + description + ": premature end of stream after " + totalBytesRead + " bytes");
			}
			totalBytesRead += bytesRead;
		}
	}
}
