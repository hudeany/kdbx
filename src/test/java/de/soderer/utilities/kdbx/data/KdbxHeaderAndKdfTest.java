package de.soderer.utilities.kdbx.data;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxVersion;
import de.soderer.utilities.kdbx.data.KdbxConstants.KeyDerivationFunction;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.utilities.TypeLengthValueStructure;
import de.soderer.utilities.kdbx.utilities.Utilities;
import de.soderer.utilities.kdbx.utilities.VariantDictionary;
import de.soderer.utilities.kdbx.utilities.VariantDictionaryEntry;
import de.soderer.utilities.kdbx.utilities.Version;

/**
 * Tests of the key derivation function parameters and the outer and inner headers of KDBX 3 and KDBX 4.
 */
@SuppressWarnings("static-method")
public class KdbxHeaderAndKdfTest {
	private static final byte[] COMPOSITE_KEY = new byte[32];
	static {
		Arrays.fill(COMPOSITE_KEY, (byte) 0x11);
	}

	// ---- AES KDF ----

	@Test
	public void testAesKdfLimits() {
		final KeyDerivationFunctionInfoAes kdf = new KeyDerivationFunctionInfoAes();
		assertEquals(60000, kdf.getAesTransformRounds());
		assertThrows(IllegalArgumentException.class, () -> kdf.setAesTransformRounds(0));
		assertThrows(IllegalArgumentException.class, () -> kdf.setAesTransformRounds(KeyDerivationFunctionInfoAes.MAX_AES_TRANSFORM_ROUNDS + 1));
		kdf.setAesTransformRounds(KeyDerivationFunctionInfoAes.MAX_AES_TRANSFORM_ROUNDS);
		assertThrows(IllegalArgumentException.class, () -> kdf.setAesTransformSeed(new byte[16]));
		kdf.setAesTransformSeed(null);
		assertNull(kdf.getAesTransformSeed());
	}

	@Test
	public void testAesKdfParametersRoundTrip() throws Exception {
		for (final KeyDerivationFunctionInfoAes.KdbxType type : KeyDerivationFunctionInfoAes.KdbxType.values()) {
			final KeyDerivationFunctionInfoAes kdf = new KeyDerivationFunctionInfoAes().withAesTransformRounds(1234);
			kdf.setAesKdbxType(type);
			final byte[] parameters = kdf.getKdfParamsBytes();
			// A random seed is created for writing
			assertEquals(32, kdf.getAesTransformSeed().length);

			final KeyDerivationFunctionInfoAes readKdf = new KeyDerivationFunctionInfoAes().withValues(VariantDictionary.read(new ByteArrayInputStream(parameters)));
			assertSame(type, readKdf.getAesKdbxType());
			assertEquals(1234, readKdf.getAesTransformRounds());
			assertArrayEquals(kdf.getAesTransformSeed(), readKdf.getAesTransformSeed());

			kdf.resetCryptoKeys();
			assertNull(kdf.getAesTransformSeed());
		}
	}

	@Test
	public void testAesKdfInvalidParameters() {
		final VariantDictionary argonDictionary = new VariantDictionary();
		argonDictionary.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.ARGON2D.getId());
		assertTrue(assertThrows(Exception.class, () -> new KeyDerivationFunctionInfoAes().setValues(argonDictionary)).getMessage().contains("Invalid KeyDerivationFunction"));

		final VariantDictionary missingSeed = new VariantDictionary();
		missingSeed.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.AES_KDBX4.getId());
		missingSeed.put(VariantDictionary.KDF_AES_ROUNDS, VariantDictionaryEntry.Type.UINT_64, 10L);
		assertTrue(assertThrows(Exception.class, () -> new KeyDerivationFunctionInfoAes().setValues(missingSeed)).getMessage().contains("Missing AES KDF parameter 'S'"));

		final VariantDictionary missingRounds = new VariantDictionary();
		missingRounds.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.AES_KDBX3.getId());
		missingRounds.put(VariantDictionary.KDF_AES_SEED, VariantDictionaryEntry.Type.BYTE_ARRAY, new byte[32]);
		assertTrue(assertThrows(Exception.class, () -> new KeyDerivationFunctionInfoAes().setValues(missingRounds)).getMessage().contains("Missing AES KDF parameter 'R'"));
	}

	// ---- Argon2 KDF ----

	@Test
	public void testArgonKdfLimits() {
		final KeyDerivationFunctionInfoArgon kdf = new KeyDerivationFunctionInfoArgon();
		assertSame(KeyDerivationFunctionInfoArgon.Argon2Type.Argon2_D, kdf.getType());
		kdf.setType(KeyDerivationFunctionInfoArgon.Argon2Type.Argon2_ID);
		kdf.setType(null);
		assertSame(KeyDerivationFunctionInfoArgon.Argon2Type.Argon2_D, kdf.getType());

		assertThrows(IllegalArgumentException.class, () -> kdf.setIterations(0));
		assertThrows(IllegalArgumentException.class, () -> kdf.setIterations(1001));
		assertThrows(IllegalArgumentException.class, () -> kdf.setMemoryInBytes(0));
		assertThrows(IllegalArgumentException.class, () -> kdf.setMemoryInBytes(2L * 1024 * 1024 * 1024 + 1));
		assertThrows(IllegalArgumentException.class, () -> kdf.setParallelism(0));
		assertThrows(IllegalArgumentException.class, () -> kdf.setParallelism(65));
		assertThrows(IllegalArgumentException.class, () -> kdf.setVersion(0x11));
		kdf.setVersion(0x13);
		kdf.setVersion(0x10);
		assertEquals(0x10, kdf.getVersion());
		assertEquals(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id, KeyDerivationFunctionInfoArgon.Argon2Type.Argon2_ID.getArgon2TypeID());
	}

	@Test
	public void testArgonKdfParametersRoundTrip() throws Exception {
		for (final KeyDerivationFunctionInfoArgon.Argon2Type type : KeyDerivationFunctionInfoArgon.Argon2Type.values()) {
			final KeyDerivationFunctionInfoArgon kdf = new KeyDerivationFunctionInfoArgon().withType(type).withIterations(3).withMemoryInBytes(2 * 1024 * 1024).withParallelism(4).withVersion(0x10);
			final byte[] parameters = kdf.getKdfParamsBytes();
			assertEquals(32, kdf.getSalt().length);

			final KeyDerivationFunctionInfoArgon readKdf = new KeyDerivationFunctionInfoArgon().withValues(VariantDictionary.read(new ByteArrayInputStream(parameters)));
			assertSame(type, readKdf.getType());
			assertEquals(3, readKdf.getIterations());
			assertEquals(2 * 1024 * 1024, readKdf.getMemoryInBytes());
			assertEquals(4, readKdf.getParallelism());
			assertEquals(0x10, readKdf.getVersion());
			assertArrayEquals(kdf.getSalt(), readKdf.getSalt());

			kdf.resetCryptoKeys();
			assertNull(kdf.getSalt());
		}
	}

	private static VariantDictionary createArgonDictionary(final long iterations) {
		final VariantDictionary dictionary = new VariantDictionary();
		dictionary.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.ARGON2ID.getId());
		dictionary.put(VariantDictionary.KDF_ARGON2_ITERATIONS, VariantDictionaryEntry.Type.UINT_64, iterations);
		dictionary.put(VariantDictionary.KDF_ARGON2_MEMORY_IN_BYTES, VariantDictionaryEntry.Type.UINT_64, 1024L * 1024);
		dictionary.put(VariantDictionary.KDF_ARGON2_PARALLELISM, VariantDictionaryEntry.Type.UINT_32, 1);
		dictionary.put(VariantDictionary.KDF_ARGON2_SALT, VariantDictionaryEntry.Type.BYTE_ARRAY, new byte[32]);
		dictionary.put(VariantDictionary.KDF_ARGON2_VERSION, VariantDictionaryEntry.Type.UINT_32, 0x13);
		return dictionary;
	}

	@Test
	public void testArgonKdfInvalidParameters() throws Exception {
		new KeyDerivationFunctionInfoArgon().setValues(createArgonDictionary(1));

		// An unsigned 64 bit value, which would become a valid int value by narrowing
		assertThrows(IllegalArgumentException.class, () -> new KeyDerivationFunctionInfoArgon().setValues(createArgonDictionary(0x1_0000_0001L)));
		assertThrows(IllegalArgumentException.class, () -> new KeyDerivationFunctionInfoArgon().setValues(createArgonDictionary(-1)));
		assertThrows(IllegalArgumentException.class, () -> new KeyDerivationFunctionInfoArgon().setValues(createArgonDictionary(0)));

		final VariantDictionary missingSalt = createArgonDictionary(1);
		missingSalt.remove(VariantDictionary.KDF_ARGON2_SALT);
		assertTrue(assertThrows(Exception.class, () -> new KeyDerivationFunctionInfoArgon().setValues(missingSalt)).getMessage().contains("Missing Argon2 KDF parameter 'S'"));

		final VariantDictionary aesDictionary = new VariantDictionary();
		aesDictionary.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.AES_KDBX4.getId());
		assertTrue(assertThrows(Exception.class, () -> new KeyDerivationFunctionInfoArgon().setValues(aesDictionary)).getMessage().contains("Invalid KeyDerivationFunction"));
	}

	// ---- KDBX 4 header ----

	@Test
	public void testHeader4Defaults() {
		final KdbxHeaderFormat4 header = new KdbxHeaderFormat4();
		assertEquals(new Version(4, 1, 0), header.getDataFormatVersion());
		assertSame(OuterEncryptionAlgorithm.AES_256, header.getOuterEncryptionAlgorithm());
		assertSame(InnerEncryptionAlgorithm.CHACHA20, header.getInnerEncryptionAlgorithm());
		assertTrue(header.isCompressData());
		assertTrue(header.getKeyDerivationFunctionInfo() instanceof KeyDerivationFunctionInfoArgon);

		header.setOuterEncryptionAlgorithm(null);
		assertSame(OuterEncryptionAlgorithm.AES_256, header.getOuterEncryptionAlgorithm());
		header.setInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.SALSA20);
		header.setInnerEncryptionAlgorithm(null);
		assertSame(InnerEncryptionAlgorithm.CHACHA20, header.getInnerEncryptionAlgorithm());
	}

	@Test
	public void testHeader4Validation() {
		final KdbxHeaderFormat4 header = new KdbxHeaderFormat4();
		assertThrows(IllegalArgumentException.class, () -> header.setDataFormatVersion(new Version(3, 1, 0)));
		assertThrows(IllegalStateException.class, () -> header.setMasterSeed(new byte[16]));
		assertThrows(IllegalStateException.class, () -> header.setMasterSeed(null));
		assertThrows(Exception.class, () -> header.getEncryptionKey(new byte[16]));
		assertThrows(Exception.class, () -> header.getEncryptionKey(null));
	}

	@Test
	public void testHeader4WriteAndRead() throws Exception {
		final byte[] publicCustomData = new byte[] { 0x00, 0x01, 0x00 };
		final KdbxHeaderFormat4 header = new KdbxHeaderFormat4().withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.CHACHA20).withCompressData(false)
				.withKeyDerivationFunctionInfo(new KeyDerivationFunctionInfoAes().withAesTransformRounds(10)).withPublicCustomDataBytes(publicCustomData);
		final byte[] headerBytes = header.getHeaderBytes();
		// The header bytes are created once and reused
		assertSame(headerBytes, header.getHeaderBytes());
		// ChaCha20 uses a 96 bit nonce
		assertEquals(12, header.getEncryptionIV().length);
		assertEquals(32, header.getMasterSeed().length);

		final KdbxHeaderFormat4 readHeader = KdbxHeaderFormat4.read(new ByteArrayInputStream(headerBytes));
		assertArrayEquals(headerBytes, readHeader.getHeaderBytes());
		assertSame(OuterEncryptionAlgorithm.CHACHA20, readHeader.getOuterEncryptionAlgorithm());
		assertFalse(readHeader.isCompressData());
		assertArrayEquals(header.getMasterSeed(), readHeader.getMasterSeed());
		assertArrayEquals(header.getEncryptionIV(), readHeader.getEncryptionIV());
		assertArrayEquals(publicCustomData, readHeader.getPublicCustomDataBytes());
		assertEquals(10, ((KeyDerivationFunctionInfoAes) readHeader.getKeyDerivationFunctionInfo()).getAesTransformRounds());

		// Both headers derive the same key
		assertArrayEquals(header.getEncryptionKey(COMPOSITE_KEY), readHeader.getEncryptionKey(COMPOSITE_KEY));

		readHeader.resetCryptoKeys();
		assertNull(readHeader.getMasterSeed());
		assertNull(readHeader.getEncryptionIV());
		assertNull(((KeyDerivationFunctionInfoAes) readHeader.getKeyDerivationFunctionInfo()).getAesTransformSeed());
	}

	@Test
	public void testHeader4ArgonKeyDerivation() throws Exception {
		final KdbxHeaderFormat4 header = new KdbxHeaderFormat4().withKeyDerivationFunctionInfo(new KeyDerivationFunctionInfoArgon().withIterations(1).withMemoryInBytes(1024 * 1024).withParallelism(1));
		header.getHeaderBytes();
		final byte[] key1 = header.getEncryptionKey(COMPOSITE_KEY);
		assertEquals(32, key1.length);
		assertArrayEquals(key1, header.getEncryptionKey(COMPOSITE_KEY));
		assertFalse(Arrays.equals(key1, header.getEncryptionKey(new byte[32])));
	}

	@Test
	public void testHeader4UnknownKeyDerivationFunction() {
		final KdbxHeaderFormat4 header = new KdbxHeaderFormat4().withKeyDerivationFunctionInfo(new KeyDerivationFunctionInfo() {
			@Override
			public byte[] getKdfParamsBytes() {
				return new byte[0];
			}

			@Override
			public void setValues(final VariantDictionary variantDictionary) {
				// nothing to do
			}

			@Override
			public void resetCryptoKeys() {
				// nothing to do
			}
		});
		assertTrue(assertThrows(Exception.class, () -> header.getEncryptionKey(COMPOSITE_KEY)).getMessage().contains("Unknown KeyDerivationFunction"));
	}

	@Test
	public void testHeader4WithInvalidTypeId() throws Exception {
		final ByteArrayOutputStream headerStream = new ByteArrayOutputStream();
		writeFileStart(headerStream, 4);
		new TypeLengthValueStructure(99, new byte[] { 1 }).write(headerStream, true);
		assertTrue(assertThrows(Exception.class, () -> KdbxHeaderFormat4.read(new ByteArrayInputStream(headerStream.toByteArray()))).getMessage().contains("Invalid header type id: 63"));
	}

	@Test
	public void testHeader4CommentIsIgnored() throws Exception {
		final ByteArrayOutputStream headerStream = new ByteArrayOutputStream();
		writeFileStart(headerStream, 4);
		new TypeLengthValueStructure(1, new byte[] { 'x' }).write(headerStream, true);
		new TypeLengthValueStructure(0, new byte[0]).write(headerStream, true);
		final KdbxHeaderFormat4 header = KdbxHeaderFormat4.read(new ByteArrayInputStream(headerStream.toByteArray()));
		assertSame(OuterEncryptionAlgorithm.AES_256, header.getOuterEncryptionAlgorithm());
	}

	@Test
	public void testInnerHeaderWriteAndRead() throws Exception {
		final KdbxHeaderFormat4 header = new KdbxHeaderFormat4().withKeyDerivationFunctionInfo(new KeyDerivationFunctionInfoAes().withAesTransformRounds(10));
		header.getHeaderBytes();
		final de.soderer.utilities.kdbx.KdbxDatabase database = new de.soderer.utilities.kdbx.KdbxDatabase();
		database.setBinaryAttachments(Arrays.asList(new KdbxBinary().withId(0).withCompressed(true).withData(Utilities.gzip(new byte[] { 1, 2, 3 })),
				new KdbxBinary().withId(1).withCompressed(false).withData(new byte[] { 4, 5 })));
		final byte[] innerHeaderBytes = header.getInnerHeaderBytes(database);

		final KdbxHeaderFormat4 readHeader = new KdbxHeaderFormat4();
		readHeader.readInnerHeader(new ByteArrayInputStream(innerHeaderBytes));
		assertSame(InnerEncryptionAlgorithm.CHACHA20, readHeader.getInnerEncryptionAlgorithm());
		assertArrayEquals(header.getInnerEncryptionKeyBytes(), readHeader.getInnerEncryptionKeyBytes());
		assertEquals(2, readHeader.getBinaryAttachments().size());
		assertArrayEquals(new byte[] { 1, 2, 3 }, readHeader.getBinaryAttachments().get(0).getData());
		assertArrayEquals(new byte[] { 4, 5 }, readHeader.getBinaryAttachments().get(1).getData());
		assertEquals(1, readHeader.getBinaryAttachments().get(1).getId());
	}

	@Test
	public void testKdfParamsBytes() throws Exception {
		final KdbxHeaderFormat4 header = new KdbxHeaderFormat4();
		header.setKdfParamsBytes(new KeyDerivationFunctionInfoArgon().withIterations(4).getKdfParamsBytes());
		assertEquals(4, ((KeyDerivationFunctionInfoArgon) header.getKeyDerivationFunctionInfo()).getIterations());
		assertTrue(header.withKdfParamsBytes(new KeyDerivationFunctionInfoAes().getKdfParamsBytes()).getKeyDerivationFunctionInfo() instanceof KeyDerivationFunctionInfoAes);
	}

	// ---- KDBX 3 header ----

	@Test
	public void testHeader3Defaults() {
		final KdbxHeaderFormat3 header = new KdbxHeaderFormat3();
		assertEquals(new Version(3, 1, 0), header.getDataFormatVersion());
		assertEquals(60000, header.getTransformRounds());
		header.setOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.AES_128);
		header.setOuterEncryptionAlgorithm(null);
		assertSame(OuterEncryptionAlgorithm.AES_256, header.getOuterEncryptionAlgorithm());
		header.setInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.SALSA20);
		header.setInnerEncryptionAlgorithm(null);
		assertSame(InnerEncryptionAlgorithm.CHACHA20, header.getInnerEncryptionAlgorithm());
		assertThrows(IllegalArgumentException.class, () -> header.setDataFormatVersion(new Version(4, 0, 0)));
	}

	@Test
	public void testHeader3WriteAndRead() throws Exception {
		final KdbxHeaderFormat3 header = new KdbxHeaderFormat3().withTransformRounds(123).withCompressData(false).withInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.SALSA20);
		final byte[] headerBytes = header.getHeaderBytes();
		assertSame(headerBytes, header.getHeaderBytes());

		final KdbxHeaderFormat3 readHeader = KdbxHeaderFormat3.read(new ByteArrayInputStream(headerBytes));
		assertArrayEquals(headerBytes, readHeader.getHeaderBytes());
		assertEquals(123, readHeader.getTransformRounds());
		assertFalse(readHeader.isCompressData());
		assertSame(InnerEncryptionAlgorithm.SALSA20, readHeader.getInnerEncryptionAlgorithm());
		assertArrayEquals(header.getMasterSeed(), readHeader.getMasterSeed());
		assertArrayEquals(header.getTransformSeed(), readHeader.getTransformSeed());
		assertArrayEquals(header.getEncryptionIV(), readHeader.getEncryptionIV());
		assertArrayEquals(header.getInnerEncryptionKeyBytes(), readHeader.getInnerEncryptionKeyBytes());
		assertArrayEquals(header.getStreamStartBytes(), readHeader.getStreamStartBytes());
		assertArrayEquals(header.getEncryptionKey(COMPOSITE_KEY), readHeader.getEncryptionKey(COMPOSITE_KEY));

		readHeader.resetCryptoKeys();
		assertNull(readHeader.getMasterSeed());
		assertNull(readHeader.getTransformSeed());
		assertNull(readHeader.getStreamStartBytes());
	}

	@Test
	public void testHeader3KeyDerivationMatchesKeePassAlgorithm() throws Exception {
		// KeePass: SHA-256 of the two AES-ECB transformed key halves
		final byte[] transformSeed = new byte[32];
		Arrays.fill(transformSeed, (byte) 0x22);
		final KdbxHeaderFormat3 header = new KdbxHeaderFormat3().withTransformRounds(3).withTransformSeed(transformSeed);

		final javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(transformSeed, "AES"));
		byte[] transformed = COMPOSITE_KEY.clone();
		for (int i = 0; i < 3; i++) {
			transformed = cipher.doFinal(transformed);
		}
		assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(transformed), header.getEncryptionKey(COMPOSITE_KEY));
	}

	@Test
	public void testHeader3KeyDerivationErrors() {
		assertThrows(Exception.class, () -> new KdbxHeaderFormat3().withTransformSeed(new byte[32]).getEncryptionKey(new byte[31]));
		assertTrue(assertThrows(Exception.class, () -> new KdbxHeaderFormat3().getEncryptionKey(COMPOSITE_KEY)).getMessage().contains("transform seed"));
		assertThrows(Exception.class, () -> new KdbxHeaderFormat3().withTransformSeed(new byte[16]).getEncryptionKey(COMPOSITE_KEY));
	}

	@Test
	public void testHeader3WithInvalidValues() throws Exception {
		final ByteArrayOutputStream invalidTypeStream = new ByteArrayOutputStream();
		writeFileStart(invalidTypeStream, 3);
		new TypeLengthValueStructure(1, new byte[] { 'c' }).write(invalidTypeStream, false);
		new TypeLengthValueStructure(11, new byte[] { 1 }).write(invalidTypeStream, false);
		assertTrue(assertThrows(Exception.class, () -> KdbxHeaderFormat3.read(new ByteArrayInputStream(invalidTypeStream.toByteArray()))).getMessage().contains("Invalid header type id: b"));

		// Transform rounds from a manipulated file must not exceed the limit
		final ByteArrayOutputStream excessiveRoundsStream = new ByteArrayOutputStream();
		writeFileStart(excessiveRoundsStream, 3);
		new TypeLengthValueStructure(6, Utilities.getLittleEndianBytes(Long.MAX_VALUE)).write(excessiveRoundsStream, false);
		assertThrows(IllegalArgumentException.class, () -> KdbxHeaderFormat3.read(new ByteArrayInputStream(excessiveRoundsStream.toByteArray())));
	}

	// ---- Common header ----

	private static void writeFileStart(final ByteArrayOutputStream outputStream, final int majorVersion) throws Exception {
		outputStream.write(Utilities.getLittleEndianBytes(KdbxConstants.KDBX_MAGICNUMBER));
		outputStream.write(Utilities.getLittleEndianBytes(KdbxVersion.KEEPASS2.getVersionId()));
		outputStream.write(Utilities.getLittleEndianBytes((short) 1));
		outputStream.write(Utilities.getLittleEndianBytes((short) majorVersion));
	}

	@Test
	public void testReadDataFormatVersion() throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		writeFileStart(outputStream, 4);
		assertEquals(new Version(4, 1, 0), KdbxHeaderFormat.readKdbxDataFormatVersion(new ByteArrayInputStream(outputStream.toByteArray())));

		final byte[] prerelease = outputStream.toByteArray();
		System.arraycopy(Utilities.getLittleEndianBytes(KdbxVersion.KEEPASS2_PRERELEASE.getVersionId()), 0, prerelease, 4, 4);
		assertTrue(assertThrows(Exception.class, () -> KdbxHeaderFormat.readKdbxDataFormatVersion(new ByteArrayInputStream(prerelease))).getMessage().contains("Unsupported kdbx version"));

		final byte[] truncated = Arrays.copyOf(outputStream.toByteArray(), 10);
		assertTrue(assertThrows(Exception.class, () -> KdbxHeaderFormat.readKdbxDataFormatVersion(new ByteArrayInputStream(truncated))).getMessage().contains("Cannot read kdbx data format version"));
	}
}
