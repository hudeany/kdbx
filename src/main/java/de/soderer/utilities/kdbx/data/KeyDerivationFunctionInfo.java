package de.soderer.utilities.kdbx.data;

import de.soderer.utilities.kdbx.utilities.VariantDictionary;

public interface KeyDerivationFunctionInfo {
	byte[] getKdfParamsBytes() throws Exception;
	void setValues(VariantDictionary variantDictionary) throws Exception;
	void resetCryptoKeys();
}
