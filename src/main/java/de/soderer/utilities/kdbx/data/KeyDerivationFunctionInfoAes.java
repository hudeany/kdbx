package de.soderer.utilities.kdbx.data;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import de.soderer.utilities.kdbx.data.KdbxConstants.KeyDerivationFunction;
import de.soderer.utilities.kdbx.utilities.VariantDictionary;
import de.soderer.utilities.kdbx.utilities.VariantDictionaryEntry;

/**
 * AES-KDF configuration: the composite key is encrypted repeatedly with AES-256 in ECB mode using the transform seed as key.
 */
public class KeyDerivationFunctionInfoAes implements KeyDerivationFunctionInfo {
	/**
	 * Identifier variants of AES-KDF.
	 */
	public enum KdbxType {
		/**
		 * AES-KDF identifier as used by KeePass (UUID c9d9f39a-...), default.
		 */
		AES_KDBX3,
		/**
		 * AES-KDF identifier as used by KeePassXC for KDBX 4 (UUID 7c02bb82-...).
		 */
		AES_KDBX4;
	}

	/**
	 * Identifier variant of AES-KDF.
	 */
	private KdbxType aesKdbxType = KeyDerivationFunctionInfoAes.KdbxType.AES_KDBX3;
	/**
	 * Number of transform rounds (1 to 500000000).
	 */
	private long aesTransformRounds = 60000;
	/**
	 * Random transform seed (32 bytes) or null to generate one for the next write.
	 */
	private byte[] aesTransformSeed;

	/**
	 * Creates an AES-KDF configuration with 60000 transform rounds.
	 */
	public KeyDerivationFunctionInfoAes() {
		// nothing to do
	}

	/**
	 * Sanity upper bound for AES-KDF rounds, to protect against maliciously crafted KDBX files that
	 * specify an excessive round count in order to force a practically unbounded CPU-bound loop
	 * during key derivation (Denial of Service), which happens before the file's header
	 * integrity/authenticity can be verified. This limit is generous compared to any reasonable
	 * real-world KeePass configuration (KeePass itself typically uses values in the low millions).
	 */
	static final long MAX_AES_TRANSFORM_ROUNDS = 500_000_000L;

	/**
	 * Returns the identifier variant of AES-KDF.
	 *
	 * @return the identifier variant of AES-KDF
	 */
	public KdbxType getAesKdbxType() {
		return aesKdbxType;
	}

	/**
	 * Sets the identifier variant of AES-KDF.
	 *
	 * @param aesKdbxType the identifier variant of AES-KDF
	 */
	public void setAesKdbxType(final KdbxType aesKdbxType) {
		this.aesKdbxType = aesKdbxType;
	}

	/**
	 * Returns the number of transform rounds (1 to 500000000).
	 *
	 * @return the number of transform rounds (1 to 500000000)
	 */
	public long getAesTransformRounds() {
		return aesTransformRounds;
	}

	/**
	 * Sets the number of transform rounds (1 to 500000000).
	 *
	 * @param aesTransformRounds the number of transform rounds (1 to 500000000)
	 */
	public void setAesTransformRounds(final long aesTransformRounds) {
		if (aesTransformRounds <= 0) {
			throw new IllegalArgumentException("Invalid AES transform rounds value: " + aesTransformRounds);
		} else if (aesTransformRounds > MAX_AES_TRANSFORM_ROUNDS) {
			throw new IllegalArgumentException("AES transform rounds value " + aesTransformRounds + " exceeds maximum allowed value of " + MAX_AES_TRANSFORM_ROUNDS);
		}
		this.aesTransformRounds = aesTransformRounds;
	}

	/**
	 * Sets the number of transform rounds (1 to 500000000) and returns this object for method chaining.
	 *
	 * @param newAesTransformRounds the number of transform rounds (1 to 500000000)
	 * @return this object
	 */
	public KeyDerivationFunctionInfoAes withAesTransformRounds(final long newAesTransformRounds) {
		setAesTransformRounds(newAesTransformRounds);
		return this;
	}

	/**
	 * Returns the random transform seed (32 bytes) or null to generate one for the next write.
	 *
	 * @return the random transform seed (32 bytes) or null to generate one for the next write
	 */
	public byte[] getAesTransformSeed() {
		return aesTransformSeed;
	}

	/**
	 * Sets the random transform seed (32 bytes) or null to generate one for the next write.
	 *
	 * @param aesTransformSeed the random transform seed (32 bytes) or null to generate one for the next write
	 */
	public void setAesTransformSeed(final byte[] aesTransformSeed) {
		if (aesTransformSeed != null && aesTransformSeed.length != 32) {
			throw new IllegalArgumentException("AES transform seed must have 32 bytes, but had " + aesTransformSeed.length);
		}
		this.aesTransformSeed = aesTransformSeed;
	}

	/**
	 * Sets the random transform seed (32 bytes) or null to generate one for the next write and returns this object for method chaining.
	 *
	 * @param newAesTransformSeed the random transform seed (32 bytes) or null to generate one for the next write
	 * @return this object
	 */
	public KeyDerivationFunctionInfoAes withAesTransformSeed(final byte[] newAesTransformSeed) {
		setAesTransformSeed(newAesTransformSeed);
		return this;
	}

	@Override
	public byte[] getKdfParamsBytes() throws Exception {
		final VariantDictionary variantDictionary = new VariantDictionary();
		if (getAesKdbxType() == KdbxType.AES_KDBX3) {
			variantDictionary.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.AES_KDBX3.getId());
		} else {
			variantDictionary.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.AES_KDBX4.getId());
		}
		variantDictionary.put(VariantDictionary.KDF_AES_ROUNDS, VariantDictionaryEntry.Type.UINT_64, aesTransformRounds);
		if (aesTransformSeed == null) {
			aesTransformSeed = new byte[32];
			new SecureRandom().nextBytes(aesTransformSeed);
		}
		variantDictionary.put(VariantDictionary.KDF_AES_SEED, VariantDictionaryEntry.Type.BYTE_ARRAY, aesTransformSeed);
		final ByteArrayOutputStream bufferStream = new ByteArrayOutputStream();
		variantDictionary.write(bufferStream);
		return bufferStream.toByteArray();
	}

	@Override
	public void setValues(final VariantDictionary variantDictionary) throws Exception {
		final KeyDerivationFunction keyDerivationFunction = KeyDerivationFunction.getById((byte[]) variantDictionary.get(VariantDictionary.KDF_UUID).getJavaValue());
		if (keyDerivationFunction == KeyDerivationFunction.AES_KDBX3) {
			setAesKdbxType(KeyDerivationFunctionInfoAes.KdbxType.AES_KDBX3);
		} else if (keyDerivationFunction == KeyDerivationFunction.AES_KDBX4) {
			setAesKdbxType(KeyDerivationFunctionInfoAes.KdbxType.AES_KDBX4);
		} else {
			throw new Exception("Invalid KeyDerivationFunction (KDF) for KeyDerivationFunctionInfoAes: " + keyDerivationFunction);
		}
		final VariantDictionaryEntry roundsEntry = variantDictionary.get(VariantDictionary.KDF_AES_ROUNDS);
		final VariantDictionaryEntry seedEntry = variantDictionary.get(VariantDictionary.KDF_AES_SEED);
		if (roundsEntry == null || seedEntry == null) {
			throw new Exception("Missing AES KDF parameter '" + (roundsEntry == null ? VariantDictionary.KDF_AES_ROUNDS : VariantDictionary.KDF_AES_SEED) + "'");
		}
		setAesTransformRounds(((Number) roundsEntry.getJavaValue()).longValue());
		setAesTransformSeed((byte[]) seedEntry.getJavaValue());
	}

	/**
	 * Sets the parameters from a VariantDictionary and returns this object for method chaining.
	 *
	 * @param newVariantDictionary the parameters
	 * @return this object
	 * @throws Exception if parameters are missing or invalid
	 */
	public KeyDerivationFunctionInfoAes withValues(final VariantDictionary newVariantDictionary) throws Exception {
		setValues(newVariantDictionary);
		return this;
	}

	@Override
	public void resetCryptoKeys() {
		aesTransformSeed = null;
	}
}
