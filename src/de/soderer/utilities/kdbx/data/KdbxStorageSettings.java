package de.soderer.utilities.kdbx.data;

import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.util.Version;

public interface KdbxStorageSettings {
	Version getDataFormatVersion();
	KdbxStorageSettings setDataFormatVersion(final Version dataFormatVersion);
	boolean isCompressData();
	KdbxStorageSettings setCompressData(final boolean compressData);
	OuterEncryptionAlgorithm getOuterEncryptionAlgorithm();
	KdbxStorageSettings setOuterEncryptionAlgorithm(final OuterEncryptionAlgorithm outerEncryptionAlgorithm);
	InnerEncryptionAlgorithm getInnerEncryptionAlgorithm();
	KdbxStorageSettings setInnerEncryptionAlgorithm(final InnerEncryptionAlgorithm innerEncryptionAlgorithm);
}
