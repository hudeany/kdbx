package de.soderer.utilities.kdbx.data;

import de.soderer.utilities.kdbx.utilities.VariantDictionary;

/**
 * Key derivation function and its parameters for KDBX 4.x files, stored as VariantDictionary in the outer header.
 */
public interface KeyDerivationFunctionInfo {
	/**
	 * Returns the binary representation (VariantDictionary) of the key derivation function and its parameters.
	 * A random salt or seed is generated, if none is set.
	 *
	 * @return the binary representation
	 * @throws Exception if the data cannot be created
	 */
	byte[] getKdfParamsBytes() throws Exception;
	/**
	 * Sets the parameters from a VariantDictionary.
	 *
	 * @param variantDictionary the parameters
	 * @throws Exception if parameters are missing or invalid
	 */
	void setValues(VariantDictionary variantDictionary) throws Exception;
	/**
	 * Discards the random salt or seed, so that a new one is generated for the next write.
	 */
	void resetCryptoKeys();
}
