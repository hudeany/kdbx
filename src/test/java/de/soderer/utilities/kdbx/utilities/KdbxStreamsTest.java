package de.soderer.utilities.kdbx.utilities;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * Tests of {@link CopyInputStream}, {@link HmacInputStream} and {@link HmacOutputStream}.
 */
@SuppressWarnings("static-method")
public class KdbxStreamsTest {
	private static final byte[] KEY = new byte[64];
	static {
		Arrays.fill(KEY, (byte) 7);
	}

	private static byte[] randomData(final int length) {
		final byte[] data = new byte[length];
		new Random(length).nextBytes(data);
		return data;
	}

	private static byte[] writeHmacBlocks(final byte[] data, final ByteOrder byteOrder) throws IOException {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (HmacOutputStream hmacOutputStream = new HmacOutputStream(outputStream, KEY)) {
			hmacOutputStream.withByteOrder(byteOrder);
			hmacOutputStream.write(data);
		}
		return outputStream.toByteArray();
	}

	private static byte[] readHmacBlocks(final byte[] blockData, final ByteOrder byteOrder) throws IOException {
		try (HmacInputStream hmacInputStream = new HmacInputStream(new ByteArrayInputStream(blockData), KEY)) {
			hmacInputStream.withByteOrder(byteOrder);
			return Utilities.toByteArray(hmacInputStream);
		}
	}

	// ---- CopyInputStream ----

	@Test
	public void testCopyInputStream() throws Exception {
		final byte[] data = randomData(100);
		try (CopyInputStream copyInputStream = new CopyInputStream(new ByteArrayInputStream(data))) {
			// Without copying nothing is stored
			assertEquals(data[0] & 0xFF, copyInputStream.read());
			assertNull(copyInputStream.getCopiedData());

			copyInputStream.setCopyOnRead(true);
			// A second activation keeps the copied data
			copyInputStream.withCopyOnRead(true);
			final int byte1 = copyInputStream.read();
			final byte[] buffer = new byte[10];
			assertEquals(10, copyInputStream.read(buffer));
			assertEquals(5, copyInputStream.read(buffer, 2, 5));
			final byte[] expectedCopy = Arrays.copyOfRange(data, 1, 17);
			assertArrayEquals(expectedCopy, copyInputStream.getCopiedData());
			assertEquals(data[1] & 0xFF, byte1);

			copyInputStream.setCopyOnRead(false);
			assertNull(copyInputStream.getCopiedData());
			copyInputStream.read(new byte[100]);
			// End of stream is not copied
			copyInputStream.setCopyOnRead(true);
			assertEquals(-1, copyInputStream.read());
			assertEquals(-1, copyInputStream.read(buffer));
			assertEquals(-1, copyInputStream.read(buffer, 0, 1));
			assertEquals(0, copyInputStream.getCopiedData().length);
		}
	}

	@Test
	public void testCopyInputStreamClose() throws Exception {
		try (final CopyInputStream copyInputStream = new CopyInputStream(new ByteArrayInputStream(new byte[1]))) {
			copyInputStream.close();
			// A second close does nothing
			copyInputStream.close();
			assertThrows(IllegalArgumentException.class, () -> new CopyInputStream(null));
		}
	}

	// ---- HMAC block streams ----

	@Test
	public void testHmacStreamsRoundTrip() throws Exception {
		for (final ByteOrder byteOrder : new ByteOrder[] { ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN }) {
			// Several blocks of 1 MiB and a partial block
			for (final byte[] data : new byte[][] { new byte[0], randomData(10), randomData(2 * 1024 * 1024 + 123) }) {
				assertArrayEquals(data, readHmacBlocks(writeHmacBlocks(data, byteOrder), byteOrder));
			}
		}
	}

	@Test
	public void testHmacBlockFormat() throws Exception {
		final byte[] blockData = writeHmacBlocks(new byte[] { 1, 2, 3 }, ByteOrder.LITTLE_ENDIAN);
		// Block 0: 32 bytes HMAC, 4 bytes length, 3 bytes data. Block 1: 32 bytes HMAC, 4 bytes length 0
		assertEquals(32 + 4 + 3 + 32 + 4, blockData.length);
		assertArrayEquals(new byte[] { 3, 0, 0, 0 }, Arrays.copyOfRange(blockData, 32, 36));
		assertArrayEquals(new byte[] { 0, 0, 0, 0 }, Arrays.copyOfRange(blockData, blockData.length - 4, blockData.length));
	}

	@Test
	public void testHmacSingleByteWritesAndReads() throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (HmacOutputStream hmacOutputStream = new HmacOutputStream(outputStream, KEY)) {
			for (int i = 0; i < 300; i++) {
				hmacOutputStream.write(i);
			}
			// Finalizing creates a block boundary, an empty finalize does nothing
			hmacOutputStream.finalizeBlockByHmacChecksum();
			hmacOutputStream.finalizeBlockByHmacChecksum();
			hmacOutputStream.write(new byte[] { 9, 8, 7 }, 1, 2);
		}

		try (HmacInputStream hmacInputStream = new HmacInputStream(new ByteArrayInputStream(outputStream.toByteArray()), KEY)) {
			for (int i = 0; i < 300; i++) {
				assertEquals(i & 0xFF, hmacInputStream.read());
			}
			assertEquals(8, hmacInputStream.read());
			assertEquals(7, hmacInputStream.read());
			assertEquals(-1, hmacInputStream.read());
			assertEquals(-1, hmacInputStream.read(new byte[5]));
			assertEquals(0, hmacInputStream.read(new byte[5], 0, 0));
		}
	}

	@Test
	public void testHmacSingleByteWriteOfFullBlock() throws Exception {
		final byte[] data = randomData(1024 * 1024 + 1);
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (HmacOutputStream hmacOutputStream = new HmacOutputStream(outputStream, KEY)) {
			for (final byte dataByte : data) {
				hmacOutputStream.write(dataByte);
			}
		}
		assertArrayEquals(data, readHmacBlocks(outputStream.toByteArray(), ByteOrder.LITTLE_ENDIAN));
	}

	@Test
	public void testHmacStreamsWithOtherAlgorithms() throws Exception {
		final byte[] data = randomData(100);
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (HmacOutputStream hmacOutputStream = new HmacOutputStream(outputStream, KEY)) {
			hmacOutputStream.withHmacAlgorithmName("HmacSHA256").withKeyHashDigestName("SHA-256");
			hmacOutputStream.write(data);
		}
		final byte[] blockData = outputStream.toByteArray();
		try (HmacInputStream hmacInputStream = new HmacInputStream(new ByteArrayInputStream(blockData), KEY)) {
			hmacInputStream.withHmacAlgorithmName("HmacSHA256").withKeyHashDigestName("SHA-256");
			assertArrayEquals(data, Utilities.toByteArray(hmacInputStream));
		}
		// The default key hash (SHA-512) creates other block keys
		assertThrows(IOException.class, () -> readHmacBlocks(blockData, ByteOrder.LITTLE_ENDIAN));
	}

	@Test
	public void testHmacUnknownAlgorithms() throws Exception {
		// The failing block stays buffered, so close() fails again: the stream is closed within assertThrows
		assertThrows(RuntimeException.class, () -> {
			try (final HmacOutputStream unknownDigestOutputStream = new HmacOutputStream(new ByteArrayOutputStream(), KEY)) {
				unknownDigestOutputStream.withKeyHashDigestName("NO-SUCH-DIGEST");
				unknownDigestOutputStream.write(1);
			}
		});

		assertThrows(RuntimeException.class, () -> {
			try (final HmacOutputStream unknownHmacOutputStream = new HmacOutputStream(new ByteArrayOutputStream(), KEY)) {
				unknownHmacOutputStream.withHmacAlgorithmName("NoSuchHmac");
				unknownHmacOutputStream.write(1);
			}
		});

		final byte[] blockData = writeHmacBlocks(new byte[] { 1 }, ByteOrder.LITTLE_ENDIAN);
		try (HmacInputStream unknownDigestInputStream = new HmacInputStream(new ByteArrayInputStream(blockData), KEY)) {
			unknownDigestInputStream.withKeyHashDigestName("NO-SUCH-DIGEST");
			assertThrows(RuntimeException.class, unknownDigestInputStream::read);
		}
		try (HmacInputStream unknownHmacInputStream = new HmacInputStream(new ByteArrayInputStream(blockData), KEY)) {
			unknownHmacInputStream.withHmacAlgorithmName("NoSuchHmac");
			assertThrows(RuntimeException.class, unknownHmacInputStream::read);
		}
	}

	@Test
	public void testHmacTamperedData() throws Exception {
		final byte[] blockData = writeHmacBlocks(randomData(100), ByteOrder.LITTLE_ENDIAN);

		final byte[] tamperedData = blockData.clone();
		tamperedData[40] ^= 1;
		assertTrue(assertThrows(IOException.class, () -> readHmacBlocks(tamperedData, ByteOrder.LITTLE_ENDIAN)).getMessage().contains("HMAC check failed"));

		final byte[] otherKey = KEY.clone();
		otherKey[0] = 0;
		try (HmacInputStream hmacInputStream = new HmacInputStream(new ByteArrayInputStream(blockData), otherKey)) {
			assertThrows(IOException.class, hmacInputStream::read);
		}

		// Data written with another byte order is detected
		assertThrows(IOException.class, () -> readHmacBlocks(blockData, ByteOrder.BIG_ENDIAN));
	}

	@Test
	public void testHmacTruncatedData() throws Exception {
		final byte[] blockData = writeHmacBlocks(randomData(100), ByteOrder.LITTLE_ENDIAN);
		assertTrue(assertThrows(IOException.class, () -> readHmacBlocks(Arrays.copyOf(blockData, 10), ByteOrder.LITTLE_ENDIAN)).getMessage().contains("terminating HMAC block is missing"));
		assertTrue(assertThrows(IOException.class, () -> readHmacBlocks(Arrays.copyOf(blockData, 34), ByteOrder.LITTLE_ENDIAN)).getMessage().contains("Cannot read HMAC block size"));
		assertTrue(assertThrows(IOException.class, () -> readHmacBlocks(Arrays.copyOf(blockData, 50), ByteOrder.LITTLE_ENDIAN)).getMessage().contains("Premature end of input"));
		// Missing terminating block
		assertTrue(assertThrows(IOException.class, () -> readHmacBlocks(Arrays.copyOf(blockData, blockData.length - 36), ByteOrder.LITTLE_ENDIAN)).getMessage().contains("terminating HMAC block is missing"));
	}

	@Test
	public void testHmacInvalidBlockSizes() throws Exception {
		final byte[] negativeSize = Utilities.concatArrays(new byte[32], Utilities.getLittleEndianBytes(-1));
		assertTrue(assertThrows(IOException.class, () -> readHmacBlocks(negativeSize, ByteOrder.LITTLE_ENDIAN)).getMessage().contains("Invalid HMAC block size"));
		final byte[] excessiveSize = Utilities.concatArrays(new byte[32], Utilities.getLittleEndianBytes(Integer.MAX_VALUE));
		assertTrue(assertThrows(IOException.class, () -> readHmacBlocks(excessiveSize, ByteOrder.LITTLE_ENDIAN)).getMessage().contains("exceeds maximum allowed size"));
	}

	@Test
	public void testHmacInvalidParameters() {
		assertThrows(IllegalArgumentException.class, () -> new HmacInputStream(null, KEY));
		assertThrows(IllegalArgumentException.class, () -> new HmacInputStream(new ByteArrayInputStream(new byte[0]), null));
		assertThrows(IllegalArgumentException.class, () -> new HmacInputStream(new ByteArrayInputStream(new byte[0]), new byte[0]));
		assertThrows(IllegalArgumentException.class, () -> new HmacInputStream(new ByteArrayInputStream(new byte[0]), new byte[32]));
		assertThrows(IllegalArgumentException.class, () -> new HmacOutputStream(null, KEY));
		assertThrows(IllegalArgumentException.class, () -> new HmacOutputStream(new ByteArrayOutputStream(), null));
		assertThrows(IllegalArgumentException.class, () -> new HmacOutputStream(new ByteArrayOutputStream(), new byte[0]));
		assertThrows(IllegalArgumentException.class, () -> new HmacOutputStream(new ByteArrayOutputStream(), new byte[32]));
	}

	@Test
	public void testHmacInvalidOffsets() throws Exception {
		try (HmacOutputStream hmacOutputStream = new HmacOutputStream(new ByteArrayOutputStream(), KEY)) {
			assertThrows(IndexOutOfBoundsException.class, () -> hmacOutputStream.write(new byte[5], -1, 1));
			assertThrows(IndexOutOfBoundsException.class, () -> hmacOutputStream.write(new byte[5], 0, -1));
			assertThrows(IndexOutOfBoundsException.class, () -> hmacOutputStream.write(new byte[5], 3, 3));
		}
		try (HmacInputStream hmacInputStream = new HmacInputStream(new ByteArrayInputStream(new byte[0]), KEY)) {
			assertThrows(IndexOutOfBoundsException.class, () -> hmacInputStream.read(new byte[5], -1, 1));
			assertThrows(IndexOutOfBoundsException.class, () -> hmacInputStream.read(new byte[5], 0, -1));
			assertThrows(IndexOutOfBoundsException.class, () -> hmacInputStream.read(new byte[5], 3, 3));
		}
	}

	@Test
	public void testHmacStreamsCloseTwice() throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (final HmacOutputStream hmacOutputStream = new HmacOutputStream(outputStream, KEY)) {
			hmacOutputStream.close();
			final int length = outputStream.size();
			// The terminating block is written only once
			hmacOutputStream.close();
			assertEquals(length, outputStream.size());
		}

		try (final HmacInputStream hmacInputStream = new HmacInputStream(new ByteArrayInputStream(outputStream.toByteArray()), KEY)) {
			hmacInputStream.close();
			hmacInputStream.close();
		}
	}
}
