package de.soderer.utilities.kdbx.data;

import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.util.Version;

public class KdbxStorageSettingsFormat4 implements KdbxStorageSettings {
	private Version dataFormatVersion = new Version(4, 1, 0);
	private boolean compressData = true;
	private OuterEncryptionAlgorithm outerEncryptionAlgorithm;
	private InnerEncryptionAlgorithm innerEncryptionAlgorithm;
	// TODO KDF

	@Override
	public Version getDataFormatVersion() {
		return dataFormatVersion;
	}

	@Override
	public KdbxStorageSettingsFormat4 setDataFormatVersion(final Version dataFormatVersion) {
		if (dataFormatVersion.getMajorVersionNumber() != 4) {
			throw new IllegalArgumentException("Invalid major data version for storage format settings of version 4");
		} else {
			this.dataFormatVersion = dataFormatVersion;
			return this;
		}
	}

	@Override
	public boolean isCompressData() {
		return compressData;
	}

	@Override
	public KdbxStorageSettingsFormat4 setCompressData(final boolean compressData) {
		this.compressData = compressData;
		return this;
	}

	@Override
	public OuterEncryptionAlgorithm getOuterEncryptionAlgorithm() {
		return outerEncryptionAlgorithm;
	}

	@Override
	public KdbxStorageSettingsFormat4 setOuterEncryptionAlgorithm(final OuterEncryptionAlgorithm outerEncryptionAlgorithm) {
		this.outerEncryptionAlgorithm = outerEncryptionAlgorithm;
		return this;
	}

	@Override
	public InnerEncryptionAlgorithm getInnerEncryptionAlgorithm() {
		return innerEncryptionAlgorithm;
	}

	@Override
	public KdbxStorageSettingsFormat4 setInnerEncryptionAlgorithm(final InnerEncryptionAlgorithm innerEncryptionAlgorithm) {
		if (innerEncryptionAlgorithm == null) {
			throw new IllegalArgumentException("Inner header lacks RANDOM_STREAM_ID");
		} else {
			this.innerEncryptionAlgorithm = innerEncryptionAlgorithm;
			return this;
		}
	}
}
