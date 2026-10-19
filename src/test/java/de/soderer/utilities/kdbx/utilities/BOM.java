package de.soderer.utilities.kdbx.utilities;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Locale;

/**
 * Byte Order Mark (BOM) signatures of the Unicode encodings.
 * <p>
 * The constants are declared in detection order: the UTF-32 little-endian signature (FF FE 00 00)
 * starts with the UTF-16 little-endian signature (FF FE), so it must be checked first. Data starting
 * with FF FE 00 00 is therefore detected as UTF-32 little-endian, although it could also be UTF-16
 * little-endian data starting with a NUL character. This follows the common convention of other
 * BOM detectors.
 * </p>
 */
public enum BOM {
	/** No BOM. */
	NONE(new byte[] {}, null, "NONE"),

	/** UTF-32, little-endian (FF FE 00 00). Must be declared before {@link #UTF_16_LE}. */
	UTF_32_LE(new byte[] { (byte) 0xFF, (byte) 0xFE, (byte) 0x00, (byte) 0x00 }, "UTF-32LE", "UTF-32 little-endian"),

	/** UTF-32, big-endian (00 00 FE FF). */
	UTF_32_BE(new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0xFE, (byte) 0xFF }, "UTF-32BE", "UTF-32 big-endian"),

	/** UTF-8 (EF BB BF, shown as "ï»¿" when misread with ISO-8859-1 or windows-1252). */
	UTF_8(new byte[] { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF }, "UTF-8", "UTF-8"),

	/** UTF-16, little-endian (FF FE, shown as "ÿþ" when misread with ISO-8859-1). */
	UTF_16_LE(new byte[] { (byte) 0xFF, (byte) 0xFE }, "UTF-16LE", "UTF-16 little-endian"),

	/** UTF-16, big-endian (FE FF, shown as "þÿ" when misread with ISO-8859-1). */
	UTF_16_BE(new byte[] { (byte) 0xFE, (byte) 0xFF }, "UTF-16BE", "UTF-16 big-endian");

	/** BOM character U+FEFF, as decoded by readers for any UTF encoding. */
	public static final char BOM_UTF_8_CHAR = (char) 65279;

	/** First character of a UTF-8 BOM (bytes EF BB BF) misread with a single byte Latin encoding like ISO-8859-1. */
	public static final char BOM_UTF_8_CHAR_ISO_8859 = (char) 239;

	/** Maximum length of a BOM signature in bytes. */
	public static final int MAX_LENGTH = 4;

	/** Signature bytes, never handed out directly, because arrays are mutable. */
	private final byte[] bytes;

	/** Name of the charset without BOM handling this BOM belongs to, or null for {@link #NONE}. */
	private final String charsetName;

	/** Human readable description. */
	private final String description;

	/**
	 * Creates a BOM constant.
	 *
	 * @param bytes
	 *            the signature bytes
	 * @param charsetName
	 *            the name of the matching charset, or null for {@link #NONE}
	 * @param description
	 *            the human readable description
	 */
	BOM(final byte[] bytes, final String charsetName, final String description) {
		this.bytes = bytes;
		this.charsetName = charsetName;
		this.description = description;
	}

	/**
	 * Returns the bytes of this BOM signature.
	 *
	 * @return a copy of the BOM bytes, an empty array for {@link #NONE}
	 */
	public byte[] getBytes() {
		return bytes.clone();
	}

	/**
	 * Returns the length of this BOM signature.
	 *
	 * @return the number of bytes, 0 for {@link #NONE}
	 */
	public int getLength() {
		return bytes.length;
	}

	/**
	 * Returns the charset of the encoding this BOM belongs to. It does not handle the BOM itself, so
	 * the BOM bytes must be skipped before decoding.
	 *
	 * @return the charset, or null for {@link #NONE}
	 */
	public Charset getCharset() {
		return charsetName == null ? null : Charset.forName(charsetName);
	}

	/**
	 * Checks whether this BOM may occur with data in the given encoding. {@link #NONE} is compatible
	 * with every encoding. A BOM is compatible with its own charset, with the endianness detecting
	 * charsets "UTF-16" and "UTF-32", and with the BOM writing variants like "x-UTF-16LE-BOM".
	 *
	 * @param charset
	 *            the encoding to check, may be null
	 * @return true, if the BOM fits the encoding
	 */
	public boolean isCompatibleWith(final Charset charset) {
		if (this == NONE) {
			return true;
		} else if (charset == null) {
			return false;
		}

		final String name = charset.name().toUpperCase(Locale.ROOT);
		final String ownName = charsetName.toUpperCase(Locale.ROOT);
		if (name.equals(ownName) || name.equals("X-" + ownName + "-BOM")) {
			return true;
		} else if (this == UTF_16_LE || this == UTF_16_BE) {
			return name.equals("UTF-16");
		} else if (this == UTF_32_LE || this == UTF_32_BE) {
			return name.equals("UTF-32");
		} else {
			return false;
		}
	}

	/**
	 * Detects the BOM at the start of the given data.
	 *
	 * @param data
	 *            the data, may be null
	 * @return the detected BOM, or {@link #NONE}
	 */
	public static BOM detect(final byte[] data) {
		return data == null ? NONE : detect(data, data.length);
	}

	/**
	 * Detects the BOM at the start of the given data.
	 *
	 * @param data
	 *            the data, may be null
	 * @param length
	 *            the number of valid bytes at the start of the data
	 * @return the detected BOM, or {@link #NONE}
	 */
	public static BOM detect(final byte[] data, final int length) {
		if (data == null) {
			return NONE;
		}
		final int validLength = Math.min(Math.max(0, length), data.length);
		// Declaration order ensures UTF-32 LE is checked before UTF-16 LE
		for (final BOM bom : values()) {
			if (bom != NONE && bom.matches(data, validLength)) {
				return bom;
			}
		}
		return NONE;
	}

	/**
	 * Detects the BOM at the start of the given stream and skips it. All bytes following the BOM
	 * stay unread.
	 *
	 * @param inputStream
	 *            the stream to read from, must support mark and reset (like a
	 *            {@link java.io.BufferedInputStream})
	 * @return the detected and skipped BOM, or {@link #NONE}
	 * @throws IOException
	 *             if reading fails
	 * @throws IllegalArgumentException
	 *             if the stream is null or does not support mark and reset
	 */
	public static BOM detectAndSkip(final InputStream inputStream) throws IOException {
		if (inputStream == null) {
			throw new IllegalArgumentException("Invalid empty inputStream");
		} else if (!inputStream.markSupported()) {
			throw new IllegalArgumentException("InputStream must support mark and reset");
		}

		final byte[] start = new byte[MAX_LENGTH];
		inputStream.mark(MAX_LENGTH);
		int length = 0;
		try {
			// A single read may return fewer bytes than available
			while (length < MAX_LENGTH) {
				final int readBytes = inputStream.read(start, length, MAX_LENGTH - length);
				if (readBytes == -1) {
					break;
				}
				length += readBytes;
			}
		} finally {
			inputStream.reset();
		}

		final BOM bom = detect(start, length);
		int skipped = 0;
		while (skipped < bom.getLength()) {
			// skip() may skip fewer bytes, read() reliably consumes a byte already known to exist
			if (inputStream.read() == -1) {
				break;
			}
			skipped++;
		}
		return bom;
	}

	/**
	 * Checks whether the data starts with this BOM.
	 *
	 * @param data
	 *            the data
	 * @param length
	 *            the number of valid bytes at the start of the data
	 * @return true, if the data starts with this BOM signature
	 */
	private boolean matches(final byte[] data, final int length) {
		if (length < bytes.length) {
			return false;
		}
		for (int i = 0; i < bytes.length; i++) {
			if (data[i] != bytes[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns the human readable description of this BOM.
	 *
	 * @return the description
	 */
	@Override
	public String toString() {
		return description;
	}
}
