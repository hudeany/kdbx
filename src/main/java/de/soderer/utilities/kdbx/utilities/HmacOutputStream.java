package de.soderer.utilities.kdbx.utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * OutputStream to create "Hashed Message Authentication Code" (HMAC) checksums.<br />
 * Default ByteOrder is Little Endian.<br />
 * Default HmacAlgorithmName is HmacSHA256.<br />
 * Default KeyHashDigestName is SHA-512.<br />
 */
public class HmacOutputStream extends OutputStream {
	/**
	 * Data size of the HMAC blocks, as used by KeePass.
	 */
	private static final int BLOCK_SIZE = 1024*1024;

	/**
	 * The underlying stream for the HMAC blocks.
	 */
	private OutputStream baseOutputStream;
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
	 * Data of the current block, which is not written yet.
	 */
	private ByteArrayOutputStream bufferStream;

	/**
	 * Creates the stream.
	 *
	 * @param outputStream the underlying stream for the HMAC blocks
	 * @param key HMAC base key, from which the key of each block is derived
	 * @throws IllegalArgumentException if a parameter is null or the key has not 64 bytes
	 */
	public HmacOutputStream(final OutputStream outputStream, final byte[] key) {
		if (outputStream == null) {
			throw new IllegalArgumentException("Invalid empty outputStream parameter for HmacOutputStream");
		} else if (key == null || key.length <= 0) {
			throw new IllegalArgumentException("Invalid empty key parameter for HmacOutputStream");
		} else if (key.length != 64) {
			throw new IllegalArgumentException("Expected a 64-byte key but got " + key.length + " bytes");
		} else {
			baseOutputStream = outputStream;
			this.key = key;
			hmacBlockIndex = 0;
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
	public HmacOutputStream withByteOrder(final ByteOrder newByteOrder) {
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
	public HmacOutputStream withHmacAlgorithmName(final String newHmacAlgorithmName) {
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
	public HmacOutputStream withKeyHashDigestName(final String newKeyHashDigestName) {
		setKeyHashDigestName(newKeyHashDigestName);
		return this;
	}

	@Override
	public void write(final int b) throws IOException {
		if (bufferStream == null) {
			bufferStream = new ByteArrayOutputStream();
		}
		bufferStream.write(b);
		if (bufferStream.size() == BLOCK_SIZE) {
			finalizeBlockByHmacChecksum();
		}
	}

	@Override
	public void write(final byte[] data, final int offset, final int length) throws IOException {
		if (offset < 0 || length < 0 || length > data.length - offset) {
			throw new IndexOutOfBoundsException("Invalid offset " + offset + " or length " + length + " for buffer of size " + data.length);
		}
		int writeIndex = offset;
		int bytesRemaining = length;
		while (bytesRemaining > 0) {
			if (bufferStream == null) {
				bufferStream = new ByteArrayOutputStream();
			}
			final int chunkSize = Math.min(bytesRemaining, BLOCK_SIZE - bufferStream.size());
			bufferStream.write(data, writeIndex, chunkSize);
			writeIndex += chunkSize;
			bytesRemaining -= chunkSize;
			if (bufferStream.size() == BLOCK_SIZE) {
				finalizeBlockByHmacChecksum();
			}
		}
	}

	/**
	 * Writes the buffered data as HMAC block, if there is any.
	 *
	 * @throws IOException if writing fails
	 */
	public void finalizeBlockByHmacChecksum() throws IOException {
		if (bufferStream != null) {
			writeHmacBlock(bufferStream.toByteArray());
			bufferStream = null;
		}
	}

	/**
	 * Writes one HMAC block: HMAC, data length and data.
	 *
	 * @param blockData data of the block, empty for the terminating block
	 * @throws IOException if writing fails
	 */
	private void writeHmacBlock(final byte[] blockData) throws IOException {
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
		final byte[] blockLengthBytes = ByteBuffer.allocate(4).order(byteOrder).putInt(blockData.length).array();
		hmac.update(blockLengthBytes);
		hmac.update(blockData, 0, blockData.length);
		final byte[] blockHmacBytes = hmac.doFinal();
		baseOutputStream.write(blockHmacBytes);
		baseOutputStream.write(blockLengthBytes);
		baseOutputStream.write(blockData);

		hmacBlockIndex++;
	}

	@Override
	public void close() throws IOException {
		if (baseOutputStream != null) {
			finalizeBlockByHmacChecksum();

			// write final empty block to signal proper data end
			writeHmacBlock(new byte[0]);

			try {
				baseOutputStream.close();
			} finally {
				baseOutputStream = null;
			}
		}
	}
}
