package de.soderer.utilities.kdbx.data;

import java.io.IOException;
import java.io.InputStream;

import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.KdbxVersion;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.utilities.Utilities;
import de.soderer.utilities.kdbx.utilities.Version;

/**
 * Unencrypted outer header of a KDBX file with the data format version and the encryption settings.
 * <p>
 * The random crypto values (master seed, encryption IV, key derivation salt, inner stream key) are generated anew, when the header data is created for writing.
 */
public abstract class KdbxHeaderFormat {
	/**
	 * Constructor for subclasses.
	 */
	protected KdbxHeaderFormat() {
		// nothing to do
	}

	/**
	 * Reads the signatures and the data format version from the start of a KDBX file.
	 *
	 * @param inputStream stream positioned at the start of the file
	 * @return the data format version
	 * @throws Exception if the data is no KeePass 2.x database file
	 */
	public static Version readKdbxDataFormatVersion(final InputStream inputStream) throws Exception {
		int magicNumber;
		try {
			magicNumber = Utilities.readLittleEndianIntFromStream(inputStream);
		} catch (final Exception e) {
			throw new Exception("Cannot read kdbx magic number", e);
		}
		if (magicNumber != KdbxConstants.KDBX_MAGICNUMBER) {
			throw new IOException("Data does not include kdbx data (Invalid magic number " + Integer.toHexString(magicNumber) + ")");
		}

		int kdbxVersionId;
		KdbxVersion kdbxVersion;
		try {
			kdbxVersionId = Utilities.readLittleEndianIntFromStream(inputStream);
		} catch (final Exception e) {
			throw new Exception("Cannot read kdbx version number", e);
		}
		try {
			kdbxVersion = KdbxVersion.getById(kdbxVersionId);
		} catch (final Exception e) {
			throw new Exception("Invalid kdbx version: " + e.getMessage(), e);
		}
		if (kdbxVersion != KdbxVersion.KEEPASS2) {
			throw new Exception("Unsupported kdbx version: " + kdbxVersion);
		}

		try {
			final short minorDataFormatVersion = Utilities.readLittleEndianShortFromStream(inputStream);
			final short majorDataFormatVersion = Utilities.readLittleEndianShortFromStream(inputStream);
			return new Version(majorDataFormatVersion, minorDataFormatVersion, 0);
		} catch (final Exception e) {
			throw new Exception("Cannot read kdbx data format version: " + e.getMessage(), e);
		}
	}

	/**
	 * Returns the data format version.
	 *
	 * @return the data format version
	 */
	public abstract Version getDataFormatVersion();

	/**
	 * Returns the binary data of the header as stored in the file.
	 * For writing, the header data is created with new random crypto values, if it was not created yet since the last {@link #resetCryptoKeys()}.
	 *
	 * @return the header data
	 * @throws Exception if the header data cannot be created
	 */
	public abstract byte[] getHeaderBytes() throws Exception;

	/**
	 * Returns the cipher for the encryption of the payload.
	 *
	 * @return the cipher
	 */
	public abstract OuterEncryptionAlgorithm getOuterEncryptionAlgorithm();

	/**
	 * Sets the cipher for the encryption of the payload.
	 *
	 * @param outerEncryptionAlgorithm the cipher
	 */
	public abstract void setOuterEncryptionAlgorithm(OuterEncryptionAlgorithm outerEncryptionAlgorithm);

	/**
	 * Returns the stream cipher for protected values within the payload.
	 *
	 * @return the stream cipher
	 */
	public abstract InnerEncryptionAlgorithm getInnerEncryptionAlgorithm();

	/**
	 * Sets the stream cipher for protected values within the payload.
	 *
	 * @param innerEncryptionAlgorithm the stream cipher
	 */
	public abstract void setInnerEncryptionAlgorithm(InnerEncryptionAlgorithm innerEncryptionAlgorithm);

	/**
	 * Returns whether the payload is GZIP compressed.
	 *
	 * @return true for compressed payload
	 */
	public abstract boolean isCompressData();

	/**
	 * Discards the header data and all random crypto values, so that new ones are generated for the next write.
	 */
	public abstract void resetCryptoKeys();

	/**
	 * Derives the key for the payload encryption from the composite key of the credentials, using the master seed and the key derivation function of this header.
	 *
	 * @param credentialsCompositeKeyBytes the composite key hash of the credentials (32 bytes)
	 * @return the encryption key
	 * @throws Exception if the key derivation fails
	 */
	public abstract byte[] getEncryptionKey(final byte[] credentialsCompositeKeyBytes) throws Exception;
}
