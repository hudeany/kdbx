package de.soderer.utilities.kdbx;

import java.io.OutputStream;

public class KdbxWriter implements AutoCloseable {
	OutputStream outputStream;

	public KdbxWriter(final OutputStream outputStream) {
		this.outputStream = outputStream;
	}

	public void writeKdbxDatabase(final char[] password) throws Exception {
		writeKdbxDatabase(new KdbxCredentials(password));
	}

	public void writeKdbxDatabase(final KdbxCredentials credentials) throws Exception {
		// TODO
	}

	@Override
	public void close() throws Exception {
		if (outputStream != null) {
			outputStream.close();
		}
	}
}
