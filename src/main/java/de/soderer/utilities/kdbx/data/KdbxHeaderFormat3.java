package de.soderer.utilities.kdbx.data;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxVersion;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.utilities.CopyInputStream;
import de.soderer.utilities.kdbx.utilities.TypeLengthValueStructure;
import de.soderer.utilities.kdbx.utilities.Utilities;
import de.soderer.utilities.kdbx.utilities.Version;

/**
 * Outer header of a KDBX file in data format version 3.x.
 */
public class KdbxHeaderFormat3 extends KdbxHeaderFormat {
	/**
	 * Creates a header for data format version 3.1 with AES-256 encryption, compression, 60000 AES-KDF transform rounds and ChaCha20 inner stream protection.
	 */
	public KdbxHeaderFormat3() {
		// nothing to do
	}

	/**
	 * Reads the header of a KDBX 3.x file.
	 *
	 * @param inputStream stream positioned at the start of the file
	 * @return the header
	 * @throws Exception if the header is invalid or not of data format version 3.x
	 */
	public static KdbxHeaderFormat3 read(final InputStream inputStream) throws Exception {
		final CopyInputStream copyInputStream = new CopyInputStream(inputStream);
		copyInputStream.setCopyOnRead(true);

		final KdbxHeaderFormat3 header = new KdbxHeaderFormat3();

		header.setDataFormatVersion(readKdbxDataFormatVersion(copyInputStream));

		TypeLengthValueStructure nextStructure;
		while ((nextStructure = TypeLengthValueStructure.read(copyInputStream, false)).getTypeId() != 0) {
			switch(nextStructure.getTypeId()) {
				case 1:
					// COMMENT: no meaning for the data, ignored like KeePass does
					break;
				case 2:
					header.setOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.getById(nextStructure.getData()));
					break;
				case 3:
					header.setCompressData((Utilities.readIntFromLittleEndianBytes(nextStructure.getData()) & 1) == 1);
					break;
				case 4:
					header.setMasterSeed(nextStructure.getData());
					break;
				case 5:
					header.setTransformSeed(nextStructure.getData());
					break;
				case 6:
					header.setTransformRounds(Utilities.readLittleEndianValueFromByteArray(nextStructure.getData()));
					break;
				case 7:
					header.setEncryptionIV(nextStructure.getData());
					break;
				case 8:
					header.setInnerEncryptionKeyBytes(nextStructure.getData());
					break;
				case 9:
					header.setStreamStartBytes(nextStructure.getData());
					break;
				case 10:
					header.setInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.getById(Utilities.readIntFromLittleEndianBytes(nextStructure.getData())));
					break;
				default:
					throw new Exception("Invalid header type id: " + Integer.toHexString(nextStructure.getTypeId()));
			}
		}

		header.headerBytes = copyInputStream.getCopiedData();
		copyInputStream.setCopyOnRead(false);

		return header;
	}

	/**
	 * Binary data of the header as read or created for writing, or null if it must be created anew.
	 */
	private byte[] headerBytes;

	/**
	 * Data format version (3.x).
	 */
	private Version dataFormatVersion = new Version(3, 1, 0);

	//CIPHER_ID(2)
	/**
	 * Cipher for the encryption of the payload (only AES-256 is supported for KDBX 3.x).
	 */
	private OuterEncryptionAlgorithm outerEncryptionAlgorithm = OuterEncryptionAlgorithm.AES_256;

	//COMPRESSION_FLAGS(3)
	/**
	 * Whether the payload is GZIP compressed.
	 */
	private boolean compressData = true;

	//MASTER_SEED(4)
	/**
	 * Random master seed (32 bytes), as read from the file. It is generated anew for each write.
	 */
	private byte[] masterSeed;

	//TRANSFORM_SEED(5)
	/**
	 * Random AES-KDF transform seed (32 bytes), as read from the file. It is generated anew for each write.
	 */
	private byte[] transformSeed;

	//TRANSFORM_ROUNDS(6)
	/**
	 * Number of AES-KDF transform rounds (1 to 500000000).
	 */
	private long transformRounds = 60000;

	//ENCRYPTION_IV(7)
	/**
	 * Random initialization vector of the payload encryption, as read from the file. It is generated anew for each write.
	 */
	private byte[] encryptionIV;

	//PROTECTED_STREAM_KEY(8)
	/**
	 * Random key of the inner stream cipher, as read from the file. It is generated anew for each write.
	 */
	private byte[] innerEncryptionKeyBytes;

	//STREAM_START_BYTES(9)
	/**
	 * Random stream start bytes (32 bytes), which precede the encrypted payload to verify the key. They are generated anew for each write.
	 */
	private byte[] streamStartBytes;

	//INNER_RANDOM_STREAM_ID(10)
	/**
	 * Stream cipher for protected values within the payload.
	 */
	private InnerEncryptionAlgorithm innerEncryptionAlgorithm = InnerEncryptionAlgorithm.CHACHA20;

	@Override
	public byte[] getHeaderBytes() throws Exception {
		if (headerBytes == null) {
			masterSeed = new byte[32];
			new SecureRandom().nextBytes(masterSeed);

			transformSeed = new byte[32];
			new SecureRandom().nextBytes(transformSeed);

			if (outerEncryptionAlgorithm == OuterEncryptionAlgorithm.CHACHA20) {
				encryptionIV = new byte[12];
			} else {
				encryptionIV = new byte[16];
			}
			new SecureRandom().nextBytes(encryptionIV);

			innerEncryptionKeyBytes = new byte[32];
			new SecureRandom().nextBytes(innerEncryptionKeyBytes);

			streamStartBytes = new byte[32];
			new SecureRandom().nextBytes(streamStartBytes);

			final ByteArrayOutputStream outerHeaderBufferStream = new ByteArrayOutputStream();

			outerHeaderBufferStream.write(Utilities.getLittleEndianBytes(KdbxConstants.KDBX_MAGICNUMBER));
			outerHeaderBufferStream.write(Utilities.getLittleEndianBytes(KdbxVersion.KEEPASS2.getVersionId()));
			outerHeaderBufferStream.write(Utilities.getLittleEndianBytes((short) dataFormatVersion.getMinorVersionNumber()));
			outerHeaderBufferStream.write(Utilities.getLittleEndianBytes((short) dataFormatVersion.getMajorVersionNumber()));
			new TypeLengthValueStructure(2, outerEncryptionAlgorithm.getId()).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(3, Utilities.getLittleEndianBytes(compressData ? 1 : 0)).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(4, masterSeed).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(5, transformSeed).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(6, Utilities.getLittleEndianBytes(transformRounds)).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(7, encryptionIV).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(8, innerEncryptionKeyBytes).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(9, streamStartBytes).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(10, Utilities.getLittleEndianBytes(innerEncryptionAlgorithm.getId())).write(outerHeaderBufferStream, false);
			new TypeLengthValueStructure(0, new byte[] {0x0D, 0x0A, 0x0D, 0x0A}).write(outerHeaderBufferStream, false);

			headerBytes = outerHeaderBufferStream.toByteArray();
		}
		return headerBytes;
	}

	/**
	 * Returns the data format version (3.x).
	 *
	 * @return the data format version (3.x)
	 */
	@Override
	public Version getDataFormatVersion() {
		return dataFormatVersion;
	}

	/**
	 * Sets the data format version (3.x).
	 *
	 * @param dataFormatVersion the data format version (3.x)
	 */
	public void setDataFormatVersion(final Version dataFormatVersion) {
		headerBytes = null;
		if (dataFormatVersion.getMajorVersionNumber() != 3) {
			throw new IllegalArgumentException("Invalid major data version for storage format settings of version 3");
		} else {
			this.dataFormatVersion = dataFormatVersion;
		}
	}

	/**
	 * Sets the data format version (3.x) and returns this object for method chaining.
	 *
	 * @param newDataFormatVersion the data format version (3.x)
	 * @return this object
	 */
	public KdbxHeaderFormat3 withDataFormatVersion(final Version newDataFormatVersion) {
		setDataFormatVersion(newDataFormatVersion);
		return this;
	}

	/**
	 * Returns the number of AES-KDF transform rounds (1 to 500000000).
	 *
	 * @return the number of AES-KDF transform rounds (1 to 500000000)
	 */
	public long getTransformRounds() {
		return transformRounds;
	}

	/**
	 * Sets the number of AES-KDF transform rounds.
	 *
	 * @param transformRounds the number of AES-KDF transform rounds (1 to 500000000)
	 */
	public void setTransformRounds(final long transformRounds) {
		if (transformRounds <= 0) {
			throw new IllegalArgumentException("Invalid AES transform rounds value: " + Long.toUnsignedString(transformRounds));
		} else if (transformRounds > KeyDerivationFunctionInfoAes.MAX_AES_TRANSFORM_ROUNDS) {
			throw new IllegalArgumentException("AES transform rounds value " + transformRounds + " exceeds maximum allowed value of " + KeyDerivationFunctionInfoAes.MAX_AES_TRANSFORM_ROUNDS);
		}
		headerBytes = null;
		this.transformRounds = transformRounds;
	}

	/**
	 * Sets the number of AES-KDF transform rounds and returns this object for method chaining.
	 *
	 * @param newTransformRounds the number of AES-KDF transform rounds (1 to 500000000)
	 * @return this object
	 */
	public KdbxHeaderFormat3 withTransformRounds(final long newTransformRounds) {
		setTransformRounds(newTransformRounds);
		return this;
	}

	/**
	 * Returns whether the payload is GZIP compressed.
	 *
	 * @return whether the payload is GZIP compressed
	 */
	@Override
	public boolean isCompressData() {
		return compressData;
	}

	/**
	 * Sets whether the payload is GZIP compressed.
	 *
	 * @param compressData whether the payload is GZIP compressed
	 */
	public void setCompressData(final boolean compressData) {
		headerBytes = null;
		this.compressData = compressData;
	}

	/**
	 * Sets whether the payload is GZIP compressed and returns this object for method chaining.
	 *
	 * @param newCompressData whether the payload is GZIP compressed
	 * @return this object
	 */
	public KdbxHeaderFormat3 withCompressData(final boolean newCompressData) {
		setCompressData(newCompressData);
		return this;
	}

	/**
	 * Returns the cipher for the encryption of the payload (only AES-256 is supported for KDBX 3.x).
	 *
	 * @return the cipher for the encryption of the payload (only AES-256 is supported for KDBX 3.x)
	 */
	@Override
	public OuterEncryptionAlgorithm getOuterEncryptionAlgorithm() {
		return outerEncryptionAlgorithm;
	}

	/**
	 * Sets the cipher for the encryption of the payload (only AES-256 is supported for KDBX 3.x).
	 *
	 * @param outerEncryptionAlgorithm the cipher for the encryption of the payload (only AES-256 is supported for KDBX 3.x)
	 */
	@Override
	public void setOuterEncryptionAlgorithm(final OuterEncryptionAlgorithm outerEncryptionAlgorithm) {
		headerBytes = null;
		if (outerEncryptionAlgorithm == null) {
			this.outerEncryptionAlgorithm = OuterEncryptionAlgorithm.AES_256;
		} else {
			this.outerEncryptionAlgorithm = outerEncryptionAlgorithm;
		}
	}

	/**
	 * Sets the cipher for the encryption of the payload (only AES-256 is supported for KDBX 3.x) and returns this object for method chaining.
	 *
	 * @param newOuterEncryptionAlgorithm the cipher for the encryption of the payload (only AES-256 is supported for KDBX 3.x)
	 * @return this object
	 */
	public KdbxHeaderFormat3 withOuterEncryptionAlgorithm(final OuterEncryptionAlgorithm newOuterEncryptionAlgorithm) {
		setOuterEncryptionAlgorithm(newOuterEncryptionAlgorithm);
		return this;
	}

	/**
	 * Returns the stream cipher for protected values within the payload.
	 *
	 * @return the stream cipher for protected values within the payload
	 */
	@Override
	public InnerEncryptionAlgorithm getInnerEncryptionAlgorithm() {
		return innerEncryptionAlgorithm;
	}

	/**
	 * Sets the stream cipher for protected values within the payload.
	 *
	 * @param innerEncryptionAlgorithm the stream cipher for protected values within the payload
	 */
	@Override
	public void setInnerEncryptionAlgorithm(final InnerEncryptionAlgorithm innerEncryptionAlgorithm) {
		headerBytes = null;
		if (innerEncryptionAlgorithm == null) {
			this.innerEncryptionAlgorithm = InnerEncryptionAlgorithm.CHACHA20;
		} else {
			this.innerEncryptionAlgorithm = innerEncryptionAlgorithm;
		}
	}

	/**
	 * Sets the stream cipher for protected values within the payload and returns this object for method chaining.
	 *
	 * @param newInnerEncryptionAlgorithm the stream cipher for protected values within the payload
	 * @return this object
	 */
	public KdbxHeaderFormat3 withInnerEncryptionAlgorithm(final InnerEncryptionAlgorithm newInnerEncryptionAlgorithm) {
		setInnerEncryptionAlgorithm(newInnerEncryptionAlgorithm);
		return this;
	}

	/**
	 * Returns the random master seed (32 bytes), as read from the file. It is generated anew for each write.
	 *
	 * @return the random master seed (32 bytes), as read from the file. It is generated anew for each write
	 */
	public byte[] getMasterSeed() {
		return masterSeed;
	}

	/**
	 * Sets the random master seed (32 bytes), as read from the file. It is generated anew for each write.
	 *
	 * @param masterSeed the random master seed (32 bytes), as read from the file. It is generated anew for each write
	 */
	public void setMasterSeed(final byte[] masterSeed) {
		headerBytes = null;
		this.masterSeed = masterSeed;
	}

	/**
	 * Sets the random master seed (32 bytes), as read from the file. It is generated anew for each write and returns this object for method chaining.
	 *
	 * @param newMasterSeed the random master seed (32 bytes), as read from the file. It is generated anew for each write
	 * @return this object
	 */
	public KdbxHeaderFormat3 withMasterSeed(final byte[] newMasterSeed) {
		setMasterSeed(newMasterSeed);
		return this;
	}

	/**
	 * Returns the random AES-KDF transform seed (32 bytes), as read from the file. It is generated anew for each write.
	 *
	 * @return the random AES-KDF transform seed (32 bytes), as read from the file. It is generated anew for each write
	 */
	public byte[] getTransformSeed() {
		return transformSeed;
	}

	/**
	 * Sets the random AES-KDF transform seed (32 bytes), as read from the file. It is generated anew for each write.
	 *
	 * @param transformSeed the random AES-KDF transform seed (32 bytes), as read from the file. It is generated anew for each write
	 */
	public void setTransformSeed(final byte[] transformSeed) {
		headerBytes = null;
		this.transformSeed = transformSeed;
	}

	/**
	 * Sets the random AES-KDF transform seed (32 bytes), as read from the file. It is generated anew for each write and returns this object for method chaining.
	 *
	 * @param newTransformSeed the random AES-KDF transform seed (32 bytes), as read from the file. It is generated anew for each write
	 * @return this object
	 */
	public KdbxHeaderFormat3 withTransformSeed(final byte[] newTransformSeed) {
		setTransformSeed(newTransformSeed);
		return this;
	}

	/**
	 * Returns the random initialization vector of the payload encryption, as read from the file. It is generated anew for each write.
	 *
	 * @return the random initialization vector of the payload encryption, as read from the file. It is generated anew for each write
	 */
	public byte[] getEncryptionIV() {
		return encryptionIV;
	}

	/**
	 * Sets the random initialization vector of the payload encryption, as read from the file. It is generated anew for each write.
	 *
	 * @param encryptionIV the random initialization vector of the payload encryption, as read from the file. It is generated anew for each write
	 */
	public void setEncryptionIV(final byte[] encryptionIV) {
		headerBytes = null;
		this.encryptionIV = encryptionIV;
	}

	/**
	 * Sets the random initialization vector of the payload encryption, as read from the file. It is generated anew for each write and returns this object for method chaining.
	 *
	 * @param newEncryptionIV the random initialization vector of the payload encryption, as read from the file. It is generated anew for each write
	 * @return this object
	 */
	public KdbxHeaderFormat3 withEncryptionIV(final byte[] newEncryptionIV) {
		setEncryptionIV(newEncryptionIV);
		return this;
	}

	/**
	 * Returns the random key of the inner stream cipher, as read from the file. It is generated anew for each write.
	 *
	 * @return the random key of the inner stream cipher, as read from the file. It is generated anew for each write
	 */
	public byte[] getInnerEncryptionKeyBytes() {
		return innerEncryptionKeyBytes;
	}

	/**
	 * Sets the random key of the inner stream cipher, as read from the file. It is generated anew for each write.
	 *
	 * @param innerEncryptionKeyBytes the random key of the inner stream cipher, as read from the file. It is generated anew for each write
	 */
	public void setInnerEncryptionKeyBytes(final byte[] innerEncryptionKeyBytes) {
		headerBytes = null;
		this.innerEncryptionKeyBytes = innerEncryptionKeyBytes;
	}

	/**
	 * Sets the random key of the inner stream cipher, as read from the file. It is generated anew for each write and returns this object for method chaining.
	 *
	 * @param newInnerEncryptionKeyBytes the random key of the inner stream cipher, as read from the file. It is generated anew for each write
	 * @return this object
	 */
	public KdbxHeaderFormat3 withInnerEncryptionKeyBytes(final byte[] newInnerEncryptionKeyBytes) {
		setInnerEncryptionKeyBytes(newInnerEncryptionKeyBytes);
		return this;
	}

	/**
	 * Returns the random stream start bytes (32 bytes), which precede the encrypted payload to verify the key. They are generated anew for each write.
	 *
	 * @return the random stream start bytes (32 bytes), which precede the encrypted payload to verify the key. They are generated anew for each write
	 */
	public byte[] getStreamStartBytes() {
		return streamStartBytes;
	}

	/**
	 * Sets the random stream start bytes (32 bytes), which precede the encrypted payload to verify the key. They are generated anew for each write.
	 *
	 * @param streamStartBytes the random stream start bytes (32 bytes), which precede the encrypted payload to verify the key. They are generated anew for each write
	 */
	public void setStreamStartBytes(final byte[] streamStartBytes) {
		headerBytes = null;
		this.streamStartBytes = streamStartBytes;
	}

	/**
	 * Sets the random stream start bytes (32 bytes), which precede the encrypted payload to verify the key. They are generated anew for each write and returns this object for method chaining.
	 *
	 * @param newStreamStartBytes the random stream start bytes (32 bytes), which precede the encrypted payload to verify the key. They are generated anew for each write
	 * @return this object
	 */
	public KdbxHeaderFormat3 withStreamStartBytes(final byte[] newStreamStartBytes) {
		setStreamStartBytes(newStreamStartBytes);
		return this;
	}

	@Override
	public byte[] getEncryptionKey(final byte[] credentialsCompositeKeyBytes) throws Exception {
		if (credentialsCompositeKeyBytes == null || credentialsCompositeKeyBytes.length != 32) {
			throw new Exception("Cannot derive key");
		} else if (transformSeed == null || transformSeed.length != 32) {
			throw new Exception("Cannot derive key: Invalid or missing transform seed");
		}
		final byte[] resultLeft = Utilities.deriveKeyByAES(transformSeed, transformRounds, Arrays.copyOfRange(credentialsCompositeKeyBytes, 0, 16));
		final byte[] resultRight = Utilities.deriveKeyByAES(transformSeed, transformRounds, Arrays.copyOfRange(credentialsCompositeKeyBytes, 16, 32));
		final byte[] transformed = Utilities.concatArrays(resultLeft, resultRight);
		return MessageDigest.getInstance("SHA-256").digest(transformed);
	}

	@Override
	public void resetCryptoKeys() {
		headerBytes = null;
		masterSeed = null;
		transformSeed = null;
		encryptionIV = null;
		innerEncryptionKeyBytes = null;
		streamStartBytes = null;
	}
}
