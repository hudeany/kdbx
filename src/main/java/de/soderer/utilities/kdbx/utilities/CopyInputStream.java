package de.soderer.utilities.kdbx.utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * InputStream, which optionally keeps a copy of all data read from the underlying stream (e.g. to get the raw header bytes while parsing them).
 */
public class CopyInputStream extends InputStream {
	/**
	 * The underlying stream.
	 */
	private InputStream baseInputStream;

	/**
	 * Copy of the read data, or null if copying is switched off.
	 */
	private ByteArrayOutputStream bufferStream = null;

	/**
	 * Creates the stream.
	 *
	 * @param inputStream the underlying stream
	 * @throws IllegalArgumentException if the stream is null
	 */
	public CopyInputStream(final InputStream inputStream) {
		if (inputStream == null) {
			throw new IllegalArgumentException("Invalid empty inputStream parameter for CopyInputStream");
		} else {
			baseInputStream = inputStream;
		}
	}

	/**
	 * Switches copying of read data on or off. Switching it off discards the copied data, switching it on again keeps the data copied so far.
	 *
	 * @param copyOnRead true to copy read data
	 */
	public void setCopyOnRead(final boolean copyOnRead) {
		if (copyOnRead) {
			if (bufferStream == null) {
				bufferStream = new ByteArrayOutputStream();
			}
		} else {
			bufferStream = null;
		}
	}

	/**
	 * Switches copying of read data on or off and returns this object for method chaining.
	 *
	 * @param newCopyOnRead true to copy read data
	 * @return this object
	 */
	public CopyInputStream withCopyOnRead(final boolean newCopyOnRead) {
		setCopyOnRead(newCopyOnRead);
		return this;
	}

	/**
	 * Returns the data copied since copying was switched on.
	 *
	 * @return the copied data or null if copying is switched off
	 */
	public byte[] getCopiedData() {
		return bufferStream == null ? null : bufferStream.toByteArray();
	}

	@Override
	public int read() throws IOException {
		final int readByte = baseInputStream.read();
		if (readByte >= 0 && bufferStream != null) {
			bufferStream.write(readByte);
		}
		return readByte;
	}

	@Override
	public int read(final byte[] data) throws IOException {
		final int readBytes = baseInputStream.read(data);
		if (readBytes > 0 && bufferStream != null) {
			bufferStream.write(data, 0, readBytes);
		}
		return readBytes;
	}

	@Override
	public int read(final byte[] data, final int offset, final int length) throws IOException {
		final int readBytes = baseInputStream.read(data, offset, length);
		if (readBytes > 0 && bufferStream != null) {
			bufferStream.write(data, offset, readBytes);
		}
		return readBytes;
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
