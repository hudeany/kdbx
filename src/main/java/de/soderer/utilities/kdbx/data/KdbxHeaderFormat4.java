package de.soderer.utilities.kdbx.data;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import de.soderer.utilities.kdbx.KdbxDatabase;
import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxVersion;
import de.soderer.utilities.kdbx.data.KdbxConstants.KeyDerivationFunction;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.utilities.CopyInputStream;
import de.soderer.utilities.kdbx.utilities.TypeLengthValueStructure;
import de.soderer.utilities.kdbx.utilities.Utilities;
import de.soderer.utilities.kdbx.utilities.VariantDictionary;
import de.soderer.utilities.kdbx.utilities.Version;

/**
 * Outer and inner header of a KDBX file in data format version 4.x.
 * The inner header is part of the encrypted payload and contains the inner stream cipher settings and the binary attachments.
 */
public class KdbxHeaderFormat4 extends KdbxHeaderFormat {
	/**
	 * Creates a header for data format version 4.1 with AES-256 encryption, compression, Argon2d key derivation and ChaCha20 inner stream protection.
	 */
	public KdbxHeaderFormat4() {
		// nothing to do
	}

	/**
	 * Reads the outer header of a KDBX 4.x file.
	 *
	 * @param inputStream stream positioned at the start of the file
	 * @return the header
	 * @throws Exception if the header is invalid or not of data format version 4.x
	 */
	public static KdbxHeaderFormat4 read(final InputStream inputStream) throws Exception {
		final CopyInputStream copyInputStream = new CopyInputStream(inputStream);
		copyInputStream.setCopyOnRead(true);

		final KdbxHeaderFormat4 header = new KdbxHeaderFormat4();

		header.setDataFormatVersion(readKdbxDataFormatVersion(copyInputStream));

		TypeLengthValueStructure nextStructure;
		while ((nextStructure = TypeLengthValueStructure.read(copyInputStream, true)).getTypeId() != 0) {
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
				case 7:
					header.setEncryptionIV(nextStructure.getData());
					break;
				case 11:
					header.setKdfParamsBytes(nextStructure.getData());
					break;
				case 12:
					// PUBLIC_CUSTOM_DATA: unencrypted VariantDictionary of plugins, kept unchanged for writing
					header.setPublicCustomDataBytes(nextStructure.getData());
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
	 * Binary data of the outer header as read or created for writing, or null if it must be created anew.
	 */
	private byte[] headerBytes;

	/**
	 * Data format version (4.x).
	 */
	private Version dataFormatVersion = new Version(4, 1, 0);

	//CIPHER_ID(2)
	/**
	 * Cipher for the encryption of the payload (AES-256 or ChaCha20).
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

	//ENCRYPTION_IV(7)
	/**
	 * Random initialization vector of the payload encryption, as read from the file. It is generated anew for each write.
	 */
	private byte[] encryptionIV;

	//KDF_PARAMETERS(11)
	/**
	 * Key derivation function and its parameters. Default is Argon2d.
	 */
	private KeyDerivationFunctionInfo keyDerivationFunctionInfo;

	//PUBLIC_CUSTOM_DATA(12)
	/**
	 * Unencrypted public custom data of plugins (binary VariantDictionary, header field 12), which is kept unchanged when writing, or null.
	 */
	private byte[] publicCustomDataBytes;

	//Inner INNER_RANDOM_STREAM_ID(1)
	/**
	 * Stream cipher for protected values within the payload.
	 */
	private InnerEncryptionAlgorithm innerEncryptionAlgorithm = InnerEncryptionAlgorithm.CHACHA20;

	//Inner INNER_RANDOM_STREAM_KEY(2)
	/**
	 * Random key of the inner stream cipher, as read from the file. It is generated anew for each write.
	 */
	private byte[] innerEncryptionKeyBytes;

	//Inner BINARY_ATTACHMENT(3);
	/**
	 * Binary attachments of the inner header.
	 */
	private List<KdbxBinary> binaryAttachments = new ArrayList<>();

	@Override
	public byte[] getHeaderBytes() throws Exception {
		if (headerBytes == null) {
			masterSeed = new byte[32];
			new SecureRandom().nextBytes(masterSeed);

			if (outerEncryptionAlgorithm == OuterEncryptionAlgorithm.CHACHA20) {
				encryptionIV = new byte[12];
			} else {
				encryptionIV = new byte[16];
			}
			new SecureRandom().nextBytes(encryptionIV);

			innerEncryptionKeyBytes = new byte[32];
			new SecureRandom().nextBytes(innerEncryptionKeyBytes);

			final ByteArrayOutputStream outerHeaderBufferStream = new ByteArrayOutputStream();

			outerHeaderBufferStream.write(Utilities.getLittleEndianBytes(KdbxConstants.KDBX_MAGICNUMBER));
			outerHeaderBufferStream.write(Utilities.getLittleEndianBytes(KdbxVersion.KEEPASS2.getVersionId()));
			outerHeaderBufferStream.write(Utilities.getLittleEndianBytes((short) dataFormatVersion.getMinorVersionNumber()));
			outerHeaderBufferStream.write(Utilities.getLittleEndianBytes((short) dataFormatVersion.getMajorVersionNumber()));
			new TypeLengthValueStructure(2, outerEncryptionAlgorithm.getId()).write(outerHeaderBufferStream, true);
			new TypeLengthValueStructure(3, Utilities.getLittleEndianBytes(compressData ? 1 : 0)).write(outerHeaderBufferStream, true);
			new TypeLengthValueStructure(4, masterSeed).write(outerHeaderBufferStream, true);
			new TypeLengthValueStructure(7, encryptionIV).write(outerHeaderBufferStream, true);
			new TypeLengthValueStructure(11, getKeyDerivationFunctionInfo().getKdfParamsBytes()).write(outerHeaderBufferStream, true);
			if (publicCustomDataBytes != null) {
				new TypeLengthValueStructure(12, publicCustomDataBytes).write(outerHeaderBufferStream, true);
			}
			new TypeLengthValueStructure(0, new byte[] {0x0D, 0x0A, 0x0D, 0x0A}).write(outerHeaderBufferStream, true);

			headerBytes = outerHeaderBufferStream.toByteArray();
		}
		return headerBytes;
	}

	/**
	 * Creates the inner header with the inner stream cipher settings and the binary attachments of the database.
	 *
	 * @param database the database with prepared binary attachments (see {@link KdbxDatabase#validate()})
	 * @return the inner header data
	 * @throws Exception if the data cannot be created
	 */
	public byte[] getInnerHeaderBytes(final KdbxDatabase database) throws Exception {
		final ByteArrayOutputStream innerHeaderBufferStream = new ByteArrayOutputStream();
		new TypeLengthValueStructure(1, Utilities.getLittleEndianBytes(innerEncryptionAlgorithm.getId())).write(innerHeaderBufferStream, true);
		new TypeLengthValueStructure(2, innerEncryptionKeyBytes).write(innerHeaderBufferStream, true);

		for (final KdbxBinary binaryAttachment : database.getBinaryAttachments()) {
			byte[] binaryAttachmentData = binaryAttachment.getData();
			if (binaryAttachment.isCompressed()) {
				binaryAttachmentData = Utilities.gunzip(binaryAttachmentData);
			}
			final boolean isEncrypted = false;
			final byte flags = isEncrypted ? 1 : 0;
			binaryAttachmentData = Utilities.concatArrays(new byte[] { flags }, binaryAttachmentData);
			new TypeLengthValueStructure(3, binaryAttachmentData).write(innerHeaderBufferStream, true);
		}
		new TypeLengthValueStructure(0, new byte[0]).write(innerHeaderBufferStream, true);
		return innerHeaderBufferStream.toByteArray();
	}

	/**
	 * Reads the inner header from the decrypted payload and stores the inner stream cipher settings and the binary attachments.
	 *
	 * @param dataInputStream stream of the decrypted payload
	 * @throws Exception if the inner header is invalid
	 */
	public void readInnerHeader(final InputStream dataInputStream) throws Exception {
		binaryAttachments = new ArrayList<>();
		final Map<Integer, byte[]> innerHeaders = new LinkedHashMap<>();
		TypeLengthValueStructure nextInnerHeaderStructure;
		// The inner header is already authenticated by the HMAC blocks, so attachments may exceed the size limit of the outer header fields
		while ((nextInnerHeaderStructure = TypeLengthValueStructure.read(dataInputStream, true, Integer.MAX_VALUE - 8)).getTypeId() != 0) {
			if (nextInnerHeaderStructure.getTypeId() == 3) {
				// BINARY_ATTACHMENT data is referenced by entries via position id in data version 4.0 and higher
				final KdbxBinary binaryAttachment = new KdbxBinary();
				binaryAttachment.setId(binaryAttachments.size());
				byte[] databaseBinaryData = nextInnerHeaderStructure.getData();
				if (databaseBinaryData.length == 0) {
					throw new Exception("Invalid binary attachment in inner header: Missing flags byte");
				}
				// Flag 0x01 only requests in-memory protection of the attachment within the application. The data itself is not encrypted.
				databaseBinaryData = Arrays.copyOfRange(databaseBinaryData, 1, databaseBinaryData.length);
				binaryAttachment.setData(databaseBinaryData);
				binaryAttachments.add(binaryAttachment);
			} else {
				innerHeaders.put(nextInnerHeaderStructure.getTypeId(), nextInnerHeaderStructure.getData());
			}
		}

		if (!innerHeaders.containsKey(1)) {
			throw new Exception("Missing inner random stream id in inner header");
		} else if (!innerHeaders.containsKey(2)) {
			throw new Exception("Missing inner random stream key in inner header");
		}
		innerEncryptionAlgorithm = InnerEncryptionAlgorithm.getById(Utilities.readIntFromLittleEndianBytes(innerHeaders.get(1)));
		innerEncryptionKeyBytes = innerHeaders.get(2);
	}

	/**
	 * Returns the data format version (4.x).
	 *
	 * @return the data format version (4.x)
	 */
	@Override
	public Version getDataFormatVersion() {
		return dataFormatVersion;
	}

	/**
	 * Sets the data format version (4.x).
	 *
	 * @param dataFormatVersion the data format version (4.x)
	 */
	public void setDataFormatVersion(final Version dataFormatVersion) {
		headerBytes = null;
		if (dataFormatVersion.getMajorVersionNumber() != 4) {
			throw new IllegalArgumentException("Invalid major data version for storage format settings of version 4");
		} else {
			this.dataFormatVersion = dataFormatVersion;
		}
	}

	/**
	 * Sets the data format version (4.x) and returns this object for method chaining.
	 *
	 * @param newDataFormatVersion the data format version (4.x)
	 * @return this object
	 */
	public KdbxHeaderFormat4 withDataFormatVersion(final Version newDataFormatVersion) {
		setDataFormatVersion(newDataFormatVersion);
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
	public KdbxHeaderFormat4 withCompressData(final boolean newCompressData) {
		setCompressData(newCompressData);
		return this;
	}

	/**
	 * Returns the cipher for the encryption of the payload (AES-256 or ChaCha20).
	 *
	 * @return the cipher for the encryption of the payload (AES-256 or ChaCha20)
	 */
	@Override
	public OuterEncryptionAlgorithm getOuterEncryptionAlgorithm() {
		return outerEncryptionAlgorithm;
	}

	/**
	 * Sets the cipher for the encryption of the payload (AES-256 or ChaCha20).
	 *
	 * @param outerEncryptionAlgorithm the cipher for the encryption of the payload (AES-256 or ChaCha20)
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
	 * Sets the cipher for the encryption of the payload (AES-256 or ChaCha20) and returns this object for method chaining.
	 *
	 * @param newOuterEncryptionAlgorithm the cipher for the encryption of the payload (AES-256 or ChaCha20)
	 * @return this object
	 */
	public KdbxHeaderFormat4 withOuterEncryptionAlgorithm(final OuterEncryptionAlgorithm newOuterEncryptionAlgorithm) {
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
	public KdbxHeaderFormat4 withInnerEncryptionAlgorithm(final InnerEncryptionAlgorithm newInnerEncryptionAlgorithm) {
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
		if (masterSeed == null || masterSeed.length != 32) {
			throw new IllegalStateException("Master seed should have 32 bytes");
		} else {
			headerBytes = null;
			this.masterSeed = masterSeed;
		}
	}

	/**
	 * Sets the random master seed (32 bytes), as read from the file. It is generated anew for each write and returns this object for method chaining.
	 *
	 * @param newMasterSeed the random master seed (32 bytes), as read from the file. It is generated anew for each write
	 * @return this object
	 */
	public KdbxHeaderFormat4 withMasterSeed(final byte[] newMasterSeed) {
		setMasterSeed(newMasterSeed);
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
	public KdbxHeaderFormat4 withEncryptionIV(final byte[] newEncryptionIV) {
		setEncryptionIV(newEncryptionIV);
		return this;
	}

	/**
	 * Returns the key derivation function and its parameters. If none is set, an Argon2d configuration with default values is created.
	 *
	 * @return the key derivation function and its parameters. Default is Argon2d
	 */
	public KeyDerivationFunctionInfo getKeyDerivationFunctionInfo() {
		if (keyDerivationFunctionInfo == null) {
			keyDerivationFunctionInfo = new KeyDerivationFunctionInfoArgon();
		}
		return keyDerivationFunctionInfo;
	}

	/**
	 * Sets the key derivation function and its parameters. Default is Argon2d.
	 *
	 * @param keyDerivationFunctionInfo the key derivation function and its parameters. Default is Argon2d
	 */
	public void setKeyDerivationFunctionInfo(final KeyDerivationFunctionInfo keyDerivationFunctionInfo) {
		headerBytes = null;
		this.keyDerivationFunctionInfo = keyDerivationFunctionInfo;
	}

	/**
	 * Sets the key derivation function and its parameters. Default is Argon2d and returns this object for method chaining.
	 *
	 * @param newKeyDerivationFunctionInfo the key derivation function and its parameters. Default is Argon2d
	 * @return this object
	 */
	public KdbxHeaderFormat4 withKeyDerivationFunctionInfo(final KeyDerivationFunctionInfo newKeyDerivationFunctionInfo) {
		setKeyDerivationFunctionInfo(newKeyDerivationFunctionInfo);
		return this;
	}

	/**
	 * Sets the key derivation function and its parameters from their binary representation (VariantDictionary).
	 *
	 * @param kdfParamsBytes the key derivation function and its parameters from their binary representation (VariantDictionary)
	 * @throws Exception if the data is invalid or the key derivation function is not supported
	 */
	public void setKdfParamsBytes(final byte[] kdfParamsBytes) throws Exception {
		headerBytes = null;
		final VariantDictionary variantDictionary = VariantDictionary.read(new ByteArrayInputStream(kdfParamsBytes));
		final KeyDerivationFunction keyDerivationFunction = KeyDerivationFunction.getById((byte[]) variantDictionary.get(VariantDictionary.KDF_UUID).getJavaValue());
		switch (keyDerivationFunction) {
			case AES_KDBX3:
			case AES_KDBX4:
				keyDerivationFunctionInfo = new KeyDerivationFunctionInfoAes().withValues(variantDictionary);
				break;
			case ARGON2D:
			case ARGON2ID:
				keyDerivationFunctionInfo = new KeyDerivationFunctionInfoArgon().withValues(variantDictionary);
				break;
			default:
				throw new Exception("Unknown KeyDerivationFunction(KDF): " + keyDerivationFunction);
		}
	}

	/**
	 * Sets the key derivation function and its parameters from their binary representation (VariantDictionary) and returns this object for method chaining.
	 *
	 * @param newKdfParamsBytes the key derivation function and its parameters from their binary representation (VariantDictionary)
	 * @return this object
	 * @throws Exception if the data is invalid or the key derivation function is not supported
	 */
	public KdbxHeaderFormat4 withKdfParamsBytes(final byte[] newKdfParamsBytes) throws Exception {
		setKdfParamsBytes(newKdfParamsBytes);
		return this;
	}

	/**
	 * Returns the unencrypted public custom data of plugins (binary VariantDictionary, header field 12), which is kept unchanged when writing, or null.
	 *
	 * @return the unencrypted public custom data of plugins (binary VariantDictionary, header field 12), which is kept unchanged when writing, or null
	 */
	public byte[] getPublicCustomDataBytes() {
		return publicCustomDataBytes;
	}

	/**
	 * Sets the unencrypted public custom data of plugins (binary VariantDictionary, header field 12), which is kept unchanged when writing, or null.
	 *
	 * @param publicCustomDataBytes the unencrypted public custom data of plugins (binary VariantDictionary, header field 12), which is kept unchanged when writing, or null
	 */
	public void setPublicCustomDataBytes(final byte[] publicCustomDataBytes) {
		headerBytes = null;
		this.publicCustomDataBytes = publicCustomDataBytes;
	}

	/**
	 * Sets the unencrypted public custom data of plugins (binary VariantDictionary, header field 12), which is kept unchanged when writing, or null and returns this object for method chaining.
	 *
	 * @param newPublicCustomDataBytes the unencrypted public custom data of plugins (binary VariantDictionary, header field 12), which is kept unchanged when writing, or null
	 * @return this object
	 */
	public KdbxHeaderFormat4 withPublicCustomDataBytes(final byte[] newPublicCustomDataBytes) {
		setPublicCustomDataBytes(newPublicCustomDataBytes);
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
	public KdbxHeaderFormat4 withInnerEncryptionKeyBytes(final byte[] newInnerEncryptionKeyBytes) {
		setInnerEncryptionKeyBytes(newInnerEncryptionKeyBytes);
		return this;
	}

	/**
	 * Returns the binary attachments of the inner header.
	 *
	 * @return the binary attachments of the inner header
	 */
	public List<KdbxBinary> getBinaryAttachments() {
		return binaryAttachments;
	}

	/**
	 * Sets the binary attachments of the inner header.
	 *
	 * @param binaryAttachments the binary attachments of the inner header
	 */
	public void setBinaryAttachments(final List<KdbxBinary> binaryAttachments) {
		headerBytes = null;
		this.binaryAttachments = binaryAttachments;
	}

	/**
	 * Sets the binary attachments of the inner header and returns this object for method chaining.
	 *
	 * @param newBinaryAttachments the binary attachments of the inner header
	 * @return this object
	 */
	public KdbxHeaderFormat4 withBinaryAttachments(final List<KdbxBinary> newBinaryAttachments) {
		setBinaryAttachments(newBinaryAttachments);
		return this;
	}

	@Override
	public byte[] getEncryptionKey(final byte[] credentialsCompositeKeyBytes) throws Exception {
		if (credentialsCompositeKeyBytes == null || credentialsCompositeKeyBytes.length != 32) {
			throw new Exception("Cannot derive key");
		}
		final KeyDerivationFunctionInfo surrentKeyDerivationFunctionInfo = getKeyDerivationFunctionInfo();
		if (surrentKeyDerivationFunctionInfo instanceof KeyDerivationFunctionInfoAes) {
			final KeyDerivationFunctionInfoAes keyDerivationFunctionInfoAes = (KeyDerivationFunctionInfoAes) surrentKeyDerivationFunctionInfo;
			final long aesTransformRounds = keyDerivationFunctionInfoAes.getAesTransformRounds();
			final byte[] aesTransformSeed = keyDerivationFunctionInfoAes.getAesTransformSeed();
			final byte[] resultLeft = Utilities.deriveKeyByAES(aesTransformSeed, aesTransformRounds, Arrays.copyOfRange(credentialsCompositeKeyBytes, 0, 16));
			final byte[] resultRight = Utilities.deriveKeyByAES(aesTransformSeed, aesTransformRounds, Arrays.copyOfRange(credentialsCompositeKeyBytes, 16, 32));
			final byte[] transformed = Utilities.concatArrays(resultLeft, resultRight);
			return MessageDigest.getInstance("SHA-256").digest(transformed);
		} else if (surrentKeyDerivationFunctionInfo instanceof KeyDerivationFunctionInfoArgon) {
			final KeyDerivationFunctionInfoArgon keyDerivationFunctionInfoArgon = (KeyDerivationFunctionInfoArgon) surrentKeyDerivationFunctionInfo;
			final Argon2Parameters.Builder builder = new Argon2Parameters.Builder(keyDerivationFunctionInfoArgon.getType().getArgon2TypeID());
			builder.withIterations(keyDerivationFunctionInfoArgon.getIterations());
			builder.withMemoryAsKB((int) (keyDerivationFunctionInfoArgon.getMemoryInBytes() / 1024));
			builder.withParallelism(keyDerivationFunctionInfoArgon.getParallelism());
			builder.withSalt(keyDerivationFunctionInfoArgon.getSalt());
			builder.withVersion(keyDerivationFunctionInfoArgon.getVersion());

			final Argon2Parameters parameters = builder.build();
			final Argon2BytesGenerator generator = new Argon2BytesGenerator();
			generator.init(parameters);

			final byte[] output = new byte[32];
			generator.generateBytes(credentialsCompositeKeyBytes, output);
			return output;
		} else {
			throw new Exception("Unknown KeyDerivationFunction (KDF)");
		}
	}

	@Override
	public void resetCryptoKeys() {
		headerBytes = null;
		masterSeed = null;
		encryptionIV = null;
		innerEncryptionKeyBytes = null;
		if (keyDerivationFunctionInfo != null) {
			keyDerivationFunctionInfo.resetCryptoKeys();
		}
	}
}
