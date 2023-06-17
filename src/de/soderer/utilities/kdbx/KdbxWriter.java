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
		//		private void doWrite(final List<Credential> credentials, final Serializer buffer,
		//			final Duration minKeyDerivationTime, final Logger progressLogger, final boolean doHeaderHashCalculationOnly)
		//					throws IOException {


		//		if (!doHeaderHashCalculationOnly && credentials.isEmpty()) {
		//			throw new IllegalArgumentException("Missing credentials");
		//		}
		//		Validate.notNull(buffer, "buffer must not be null");
		//		Validate.notNull(progressLogger, "progressLogger must not be null");
		//
		//		if (!doHeaderHashCalculationOnly && minKeyDerivationTime != null) {
		//			// warm-up JVM before we start measuring execution times
		//			if (!warmupDone) {
		//				final KeyDerivationFunctionId kdf = outerHeader.getKDF();
		//				final long ts = System.currentTimeMillis();
		//				deriveMasterKey(credentials, kdf, 100, true);
		//				final long loopTimeMillis = System.currentTimeMillis() - ts;
		//				final int innerRounds = (int) Math.max(1, 1000 / loopTimeMillis);
		//
		//				for (int i = 0; i < 5; i++) {
		//					deriveMasterKey(credentials, kdf, innerRounds, true);
		//				}
		//				warmupDone = true;
		//			}
		//			while (true) {
		//				final long iterationCount = getTransformRounds();
		//				if (iterationCount < 1) { // maybe we overflowed ?
		//					throw new RuntimeException("Iteration count should never be or become negative");
		//				}
		//				final long now = System.currentTimeMillis();
		//				deriveMasterKey(credentials, false);
		//				final long elapsedMillis = System.currentTimeMillis() - now;
		//				if (elapsedMillis >= minKeyDerivationTime.toMillis()) {
		//					LOG.info("Using " + iterationCount + " iterations [" + elapsedMillis + " ms]");
		//					progressLogger.success("Using " + iterationCount + " iterations [" + elapsedMillis + " ms]");
		//					break;
		//				}
		//				final String msg = "Key derivation with " + iterationCount + " rounds " + "took " + elapsedMillis
		//						+ " ms which is faster than the" + " requested min. key derivation time of "
		//						+ minKeyDerivationTime.toMillis() + " ms";
		//				progressLogger.debug(msg);
		//				LOG.debug("doWrite(): " + msg);
		//				final float increment = iterationCount * 0.01f;
		//				final long newIterationCount = iterationCount + (long) increment;
		//				if (newIterationCount <= iterationCount) {
		//					throw new RuntimeException("Internal error, rounds counter must never be decreased here");
		//				}
		//				setTransformRounds(newIterationCount);
		//			}
		//			// KDBX v3.1 stores the header checksum as part of the XML payload
		//			// so we need to adjust it here as we might've changed the number of KDF rounds.
		//
		//			// KDBX v4+ does not store the header hash as part of the payload anymore
		//			if (getAppVersion().major() < 4) {
		//				new XmlPayloadView(this).setHeaderHash(calculateHeaderHash());
		//			}
		//		}
		//
		//		// write magic
		//		buffer.setWriteCopyToTmpBuffer(true);
		//		buffer.writeInt(MAGIC);
		//
		//		// write header version
		//		buffer.writeInt(outerHeader.headerVersion.magic);
		//
		//		// write app version
		//		buffer.writeShort(outerHeader.appVersion.minor());
		//		buffer.writeShort(outerHeader.appVersion.major());
		//
		//		// write header entries
		//		final Misc.ThrowingBiConsumer<TLV<TLV.OuterHeaderType>, Serializer> outerHeaderWriter;
		//		if (getAppVersion().major() < 4) {
		//			outerHeaderWriter = TLV::writeV3;
		//		} else {
		//			outerHeaderWriter = TLV::writeV4;
		//		}
		//		for (final TLV<TLV.OuterHeaderType> tlv : outerHeader.headerEntries.values()) {
		//			outerHeaderWriter.consume(tlv, buffer);
		//		}
		//
		//		if (doHeaderHashCalculationOnly) {
		//			return;
		//		}
		//
		//		byte[] hmacKey = new byte[0];
		//		final MasterKey masterKey = deriveMasterKey(credentials, false);
		//		if (getAppVersion().major() >= 4) {
		//			final byte[] headerData = buffer.getTmpBuffer();
		//
		//			// write header hash (SHA-256)
		//			buffer.writeBytes(calculateHeaderHash());
		//			hmacKey = hmacKey(outerHeader.get(TLV.OuterHeaderType.MASTER_SEED), masterKey.transformedKey);
		//
		//			final byte[] headerHmac = calculateHMAC256(headerData,
		//					HMACInputStream.getHMacKey(0xffffffff_ffffffffL, hmacKey));
		//
		//			// store HMAC-256
		//			buffer.writeBytes(headerHmac);
		//		}
		//		buffer.setWriteCopyToTmpBuffer(false);
		//
		//		// write XML payload part
		//		final ByteArrayOutputStream xmlPayload = new ByteArrayOutputStream();
		//		try (Serializer tmp = new Serializer(xmlPayload)) {
		//			if (getAppVersion().major() < 4) {
		//				xmlPayload.write(outerHeader.get(TLV.OuterHeaderType.STREAM_START_BYTES).rawValue);
		//				for (final PayloadBlock block : payloadBlocks) {
		//					block.write(tmp);
		//				}
		//			} else {
		//				final List<PayloadBlock> xml = payloadBlocks.stream()
		//						.filter(block -> block.blockId == PayloadBlock.BLOCK_ID_PAYLOAD).collect(Collectors.toList());
		//				if (xml.size() != 1) {
		//					throw new IllegalStateException("Expected exactly one payload block, got " + xml.size());
		//				}
		//				tmp.writeBytes(xml.get(0).getDecompressedPayload());
		//			}
		//		}
		//
		//		byte[] payload = xmlPayload.toByteArray();
		//		final byte[] encryptionIV = outerHeader.get(TLV.OuterHeaderType.ENCRYPTION_IV).rawValue;
		//
		//		final Misc.IOFunction<OutputStream, OutputStream> encryptedOutputStream = toWrap -> CipherStreamFactory
		//				.encryptOutputStream(outerHeader.getOuterEncryptionAlgorithm(), masterKey, encryptionIV, toWrap);
		//
		//		if (getAppVersion().major() >= 4) {
		//			// KDBX v4 -> payload is inner header followed by XML
		//			final ByteArrayOutputStream innerHeaders = new ByteArrayOutputStream();
		//			final Serializer innerHeaderSerializer = new Serializer(innerHeaders);
		//			if (getAppVersion().major() >= 4) {
		//				for (final TLV<TLV.InnerHeaderType> tlv : innerHeader.entries) {
		//					tlv.writeV4(innerHeaderSerializer);
		//				}
		//			}
		//			payload = Misc.concat(innerHeaders.toByteArray(), payload);
		//
		//			// 3. wrap with HMAC output stream
		//			buffer.wrapOutputStream(hmacKey, HMACOutputStream::new);
		//
		//			// 2. encrypt
		//			buffer.wrapOutputStream(encryptedOutputStream);
		//
		//			// 1. compress is necessary
		//			if (outerHeader.isCompressedPayload()) {
		//				buffer.wrapOutputStream(GZIPOutputStream::new);
		//			}
		//		} else {
		//			// encrypt
		//			buffer.wrapOutputStream(encryptedOutputStream);
		//		}
		//		buffer.writeBytes(payload);
	}

	@Override
	public void close() throws Exception {
		if (outputStream != null) {
			outputStream.close();
		}
	}
}
