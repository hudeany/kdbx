package de.soderer.utilities.kdbx.data;

import de.soderer.utilities.kdbx.data.KdbxConstants.InnerEncryptionAlgorithm;
import de.soderer.utilities.kdbx.data.KdbxConstants.OuterEncryptionAlgorithm;
import de.soderer.utilities.kdbx.util.Version;

public class KdbxStorageSettingsFormat3 implements KdbxStorageSettings {
	private Version dataFormatVersion = new Version(3, 1, 0);
	private long transformRounds;
	private boolean compressData = true;
	private OuterEncryptionAlgorithm outerEncryptionAlgorithm;
	private InnerEncryptionAlgorithm innerEncryptionAlgorithm;

	@Override
	public Version getDataFormatVersion() {
		return dataFormatVersion;
	}

	@Override
	public KdbxStorageSettingsFormat3 setDataFormatVersion(final Version dataFormatVersion) {
		if (dataFormatVersion.getMajorVersionNumber() != 3) {
			throw new IllegalArgumentException("Invalid major data version for storage format settings of version 3");
		} else {
			this.dataFormatVersion = dataFormatVersion;
			return this;
		}
	}

	public long getTransformRounds() {
		return transformRounds;
	}

	public KdbxStorageSettingsFormat3 setTransformRounds(final long transformRounds) {
		this.transformRounds = transformRounds;
		return this;
	}

	@Override
	public boolean isCompressData() {
		return compressData;
	}

	@Override
	public KdbxStorageSettingsFormat3 setCompressData(final boolean compressData) {
		this.compressData = compressData;
		return this;
	}

	@Override
	public OuterEncryptionAlgorithm getOuterEncryptionAlgorithm() {
		return outerEncryptionAlgorithm;
	}

	@Override
	public KdbxStorageSettingsFormat3 setOuterEncryptionAlgorithm(final OuterEncryptionAlgorithm outerEncryptionAlgorithm) {
		if (outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_128 && outerEncryptionAlgorithm != OuterEncryptionAlgorithm.AES_256) {
			throw new IllegalArgumentException("Cipher " + outerEncryptionAlgorithm + " is not implemented yet");
		} else {
			this.outerEncryptionAlgorithm = outerEncryptionAlgorithm;
			return this;
		}
	}

	@Override
	public InnerEncryptionAlgorithm getInnerEncryptionAlgorithm() {
		return innerEncryptionAlgorithm;
	}

	@Override
	public KdbxStorageSettingsFormat3 setInnerEncryptionAlgorithm(final InnerEncryptionAlgorithm innerEncryptionAlgorithm) {
		if (innerEncryptionAlgorithm == null) {
			throw new IllegalArgumentException("Inner header lacks RANDOM_STREAM_ID");
		} else {
			this.innerEncryptionAlgorithm = innerEncryptionAlgorithm;
			return this;
		}
	}
}
