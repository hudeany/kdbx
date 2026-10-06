package de.soderer.utilities.kdbx.utilities;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * InputStream to check "Hashed Message Authentication Code" (HMAC) checksums.<br />
 * Default ByteOrder is Little Endian.<br />
 * Default HmacAlgorithmName is HmacSHA256.<br />
 * Default KeyHashDigestName is SHA-512.<br />
 */
public class HmacInputStream extends InputStream {
	/**
	 * The underlying stream with HMAC blocks.
	 */
	private InputStream baseInputStream;
	/**
	 * HMAC base key, from which the key of each block is derived.
	 */
	private byte[] key;

	/**
	 * Byte order of block index and block length (default little endian).
	 */
	private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
	/**
	 * Name of the HMAC algorithm (default "HmacSHA256").
	 */
	private String hmacAlgorithmName = "HmacSHA256";
	/**
	 * Name of the digest algorithm for the derivation of the block keys (default "SHA-512").
	 */
	private String keyHashDigestName = "SHA-512";

	/**
	 * Index of the next block.
	 */
	private long hmacBlockIndex;
	/**
	 * Whether the terminating block was read.
	 */
	private boolean eof;
	/**
	 * Verified data of the current block.
	 */
	private ByteArrayInputStream bufferStream;

	/**
	 * Sanity upper bound for a single HMAC block, to protect against maliciously crafted block size
	 * values forcing huge allocations before the block's HMAC has actually been verified.
	 */
	private static final int MAX_BLOCK_SIZE = 64 * 1024 * 1024; // 64 MB

	/**
	 * Creates the stream.
	 *
	 * @param inputStream the underlying stream with HMAC blocks
	 * @param key HMAC base key, from which the key of each block is derived
	 * @throws IllegalArgumentException if a parameter is null or the key has not 64 bytes
	 */
	public HmacInputStream(final InputStream inputStream, final byte[] key) {
		if (inputStream == null) {
			throw new IllegalArgumentException("Invalid empty inputStream parameter for HmacInputStream");
		} else if (key == null || key.length <= 0) {
			throw new IllegalArgumentException("Invalid empty key parameter for HmacInputStream");
		} else if (key.length != 64) {
			throw new IllegalArgumentException("Expected a 64-byte key but got " + key.length + " bytes");
		} else {
			baseInputStream = inputStream;
			this.key = key;
			hmacBlockIndex = 0;
			eof = false;
		}
	}

	/**
	 * Sets the byte order of block index and block length (default little endian).
	 *
	 * @param byteOrder the byte order of block index and block length (default little endian)
	 */
	public void setByteOrder(final ByteOrder byteOrder) {
		this.byteOrder = byteOrder;
	}

	/**
	 * Sets the byte order of block index and block length (default little endian) and returns this object for method chaining.
	 *
	 * @param newByteOrder the byte order of block index and block length (default little endian)
	 * @return this object
	 */
	public HmacInputStream withByteOrder(final ByteOrder newByteOrder) {
		setByteOrder(newByteOrder);
		return this;
	}

	/**
	 * Sets the name of the HMAC algorithm (default "HmacSHA256").
	 *
	 * @param hmacAlgorithmName the name of the HMAC algorithm (default "HmacSHA256")
	 */
	public void setHmacAlgorithmName(final String hmacAlgorithmName) {
		this.hmacAlgorithmName = hmacAlgorithmName;
	}

	/**
	 * Sets the name of the HMAC algorithm (default "HmacSHA256") and returns this object for method chaining.
	 *
	 * @param newHmacAlgorithmName the name of the HMAC algorithm (default "HmacSHA256")
	 * @return this object
	 */
	public HmacInputStream withHmacAlgorithmName(final String newHmacAlgorithmName) {
		setHmacAlgorithmName(newHmacAlgorithmName);
		return this;
	}

	/**
	 * Sets the name of the digest algorithm for the derivation of the block keys (default "SHA-512").
	 *
	 * @param keyHashDigestName the name of the digest algorithm for the derivation of the block keys (default "SHA-512")
	 */
	public void setKeyHashDigestName(final String keyHashDigestName) {
		this.keyHashDigestName = keyHashDigestName;
	}

	/**
	 * Sets the name of the digest algorithm for the derivation of the block keys (default "SHA-512") and returns this object for method chaining.
	 *
	 * @param newKeyHashDigestName the name of the digest algorithm for the derivation of the block keys (default "SHA-512")
	 * @return this object
	 */
	public HmacInputStream withKeyHashDigestName(final String newKeyHashDigestName) {
		setKeyHashDigestName(newKeyHashDigestName);
		return this;
	}

	@Override
	public int read() throws IOException {
		while (!eof) {
			if (bufferStream != null) {
				final int readByte = bufferStream.read();
				if (readByte != -1) {
					return readByte;
				}
			}
			readNextHmacBlock();
		}
		return -1;
	}

	@Override
	public int read(final byte[] data) throws IOException {
		return read(data, 0, data.length);
	}

	@Override
	public int read(final byte[] data, final int offset, final int length) throws IOException {
		if (offset < 0 || length < 0 || length > data.length - offset) {
			throw new IndexOutOfBoundsException("Invalid offset " + offset + " or length " + length + " for buffer of size " + data.length);
		} else if (length == 0) {
			return 0;
		}

		int totalBytesRead = 0;
		while (totalBytesRead < length && !eof) {
			if (bufferStream != null) {
				final int bytesRead = bufferStream.read(data, offset + totalBytesRead, length - totalBytesRead);
				if (bytesRead > 0) {
					totalBytesRead += bytesRead;
					continue;
				}
			}
			readNextHmacBlock();
		}
		return totalBytesRead == 0 ? -1 : totalBytesRead;
	}

	/**
	 * Reads and verifies the next HMAC block.
	 * A block with data length 0 terminates the stream (KDBX 4 HmacBlockStream).
	 * A stream ending without this terminating block was truncated and is rejected.
	 *
	 * @throws IOException if the data is truncated or corrupted
	 */
	private void readNextHmacBlock() throws IOException {
		bufferStream = null;

		final byte[] hmacBytes = baseInputStream.readNBytes(32);
		if (hmacBytes.length != 32) {
			throw new IOException("Cannot read HMAC code of block " + hmacBlockIndex + ": Data is truncated, terminating HMAC block is missing");
		}

		final byte[] blockLengthBytes = baseInputStream.readNBytes(4);
		if (blockLengthBytes.length != 4) {
			throw new IOException("Cannot read HMAC block size of block " + hmacBlockIndex + ": Data is truncated");
		}

		final int nextBlockSize = ByteBuffer.wrap(blockLengthBytes).order(byteOrder).getInt();

		if (nextBlockSize < 0) {
			throw new IOException("Invalid HMAC block size: " + nextBlockSize);
		} else if (nextBlockSize > MAX_BLOCK_SIZE) {
			throw new IOException("HMAC block size " + nextBlockSize + " exceeds maximum allowed size of " + MAX_BLOCK_SIZE + " bytes");
		}

		final byte[] buffer = baseInputStream.readNBytes(nextBlockSize);
		if (buffer.length != nextBlockSize) {
			throw new IOException("Premature end of input, expected " + nextBlockSize + " bytes but got only " + buffer.length);
		}

		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(keyHashDigestName);
		} catch (final NoSuchAlgorithmException e) {
			throw new RuntimeException("Digest not available: " + keyHashDigestName, e);
		}
		digest.update(ByteBuffer.allocate(8).order(byteOrder).putLong(hmacBlockIndex).array());
		final byte[] hmacBlockKey = digest.digest(key);

		Mac hmac;
		try {
			hmac = Mac.getInstance(hmacAlgorithmName);
			hmac.init(new SecretKeySpec(hmacBlockKey, hmacAlgorithmName));
		} catch (final InvalidKeyException e) {
			throw new RuntimeException("Invalid key for digest: " + hmacAlgorithmName, e);
		} catch (final NoSuchAlgorithmException e) {
			throw new RuntimeException("Hmac algorithm not available: " + hmacAlgorithmName, e);
		}

		hmac.update(ByteBuffer.allocate(8).order(byteOrder).putLong(hmacBlockIndex).array());
		hmac.update(blockLengthBytes);
		hmac.update(buffer, 0, nextBlockSize);
		final byte[] blockHmacBytes = hmac.doFinal();
		if (!MessageDigest.isEqual(hmacBytes, blockHmacBytes)) {
			throw new IOException("HMAC check failed, data or hash value is corrupted at block " + hmacBlockIndex);
		}

		hmacBlockIndex++;
		if (nextBlockSize == 0) {
			// Empty block signals the regular end of data
			eof = true;
		} else {
			bufferStream = new ByteArrayInputStream(buffer);
		}
	}

	@Override
	public void close() throws IOException {
		if (baseInputStream != null) {
			try {
				baseInputStream.close();
			} finally {
				baseInputStream = null;
			}
		}
	}
}
