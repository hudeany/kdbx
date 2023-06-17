package de.soderer.utilities.kdbx.data;

import java.util.Arrays;

import de.soderer.utilities.kdbx.util.Utilities;

public class KdbxConstants {
	public static final int KDBX_MAGICNUMBER = 0x9AA2D903;

	public enum KdbxVersion {
		KEEPASS1(0xB54BFB65, false),
		KEEPASS2_PRERELEASE(0xB54BFB66, true),
		KEEPASS2(0xB54BFB67, true);

		private final int versionId;
		private final boolean isKeepass2;

		public int getVersionId() {
			return versionId;
		}

		public boolean isKeepass2() {
			return isKeepass2;
		}

		KdbxVersion(final int versionId, final boolean isKeepass2) {
			this.versionId = versionId;
			this.isKeepass2 = isKeepass2;
		}

		public static KdbxVersion getById(final int versionId) throws Exception {
			for (final KdbxVersion version : KdbxVersion.values()) {
				if (version.getVersionId() == versionId) {
					return version;
				}
			}
			throw new Exception("Invalid version id: " + "0x" + Integer.toHexString(versionId));
		}
	}

	public enum KdbxOuterHeaderType {
		/** ID 0: END entry, no more header entries after this */
		END_OF_HEADER(0),

		/** ID 1: COMMENT */
		COMMENT(1),

		/** ID 2: CIPHERID, bData="31c1f2e6bf714350be5805216afc5aff" => outer encryption AES256, currently no others supported */
		CIPHER_ID(2),

		/** ID 3: COMPRESSIONFLAGS, LE DWORD. 0=payload not compressed, 1=payload compressed with GZip */
		COMPRESSION_FLAGS(3),

		/** ID 4: MASTERSEED, 32 BYTEs string. See further down for usage/purpose. Length MUST be checked */
		MASTER_SEED(4),

		/** ID 5: TRANSFORMSEED, variable length BYTE string. See further down for usage/purpose */
		TRANSFORM_SEED(5),

		/** ID 6: TRANSFORMROUNDS, LE QWORD. See further down for usage/purpose */
		TRANSFORM_ROUNDS(6),

		/** ID 7: ENCRYPTIONIV, variable length BYTE string. See further down for usage/purpose */
		ENCRYPTION_IV(7),

		/** ID 8: PROTECTEDSTREAMKEY, variable length BYTE string. See further down for usage/purpose */
		PROTECTED_STREAM_KEY(8),

		/** ID 9: STREAMSTARTBYTES, variable length BYTE string. See further down for usage/purpose */
		STREAM_START_BYTES(9),

		/** ID 10: INNERRANDOMSTREAMID, LE DWORD <br />
		 * Inner stream encryption type: <br />
		 * 0=>none <br />
		 * 1=>Arc4Variant <br />
		 * 2=>Salsa20 <br />
		 * This is actually a type ID identifying the stream cipher used to sensitive content inside the XML payload. */
		INNER_RANDOM_STREAM_ID(10),

		/** ID 11 */
		KDF_PARAMETERS(11),

		/** ID 12 */
		PUBLIC_CUSTOM_DATA_PARAMETERS(12);

		private final int id;

		KdbxOuterHeaderType(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		public static KdbxOuterHeaderType getById(final int id) throws Exception {
			for (final KdbxOuterHeaderType kdbxOuterHeaderType : KdbxOuterHeaderType.values()) {
				if (kdbxOuterHeaderType.getId() == id) {
					return kdbxOuterHeaderType;
				}
			}
			throw new Exception("Invalid id: " + Integer.toHexString(id));
		}
	}

	public enum KdbxInnerHeaderType {
		/** ID 0: END entry, no more header entries after this */
		END_OF_HEADER(0),

		/**
		 * ID 1: Inner random stream ID (this supersedes the inner random stream ID stored in the outer header of a KDBX 3.1 file).
		 * This is actually a type ID identifying the stream cipher used to encrypt passwords inside the XML payload.
		 */
		INNER_RANDOM_STREAM_ID(1),

		/**
		 * ID 2: Inner random stream key used to encrypt passwords inside the XML payload
		 * TODO: Is this what is called PROTECTED_STREAM_KEY in the outer header?
		 * (this supersedes the inner random stream key stored in the outer header of a KDBX 3.1 file).
		 */
		INNER_RANDOM_STREAM_KEY(2),

		/**
		 * ID 3: Binary (entry attachment). D = F ‖ M, where F is one byte and M is the binary content (i.e. the actual entry attachment data).
		 * F stores flags for the binary; supported flags are:
		 * - 0x01: The user has turned on process memory protection for this binary.
		 */
		BINARY_ATTACHMENT(3);

		private final int id;

		KdbxInnerHeaderType(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		public static KdbxInnerHeaderType getById(final int id) throws Exception {
			for (final KdbxInnerHeaderType innerHeaderType : KdbxInnerHeaderType.values()) {
				if (innerHeaderType.getId() == id) {
					return innerHeaderType;
				}
			}
			throw new Exception("Invalid id: " + Integer.toHexString(id));
		}
	}

	public enum KeyDerivationFunction {
		AES_KDBX3(Utilities.fromHexString("c9d9f39a-628a-4460-bf74-0d08c18a4fea", true)),
		AES_KDBX4(Utilities.fromHexString("7c02bb82-79a7-4ac0-927d-114a00648238", true)),
		ARGON2D(Utilities.fromHexString("ef636ddf-8c29-444b-91f7-a9a403e30a0c", true)),
		ARGON2ID(Utilities.fromHexString("9e298b19-56db-4773-b23d-fc3ec6f0a1e6", true));

		private final byte[] id;

		public byte[] getId() {
			return id;
		}

		KeyDerivationFunction(final byte[] id) {
			this.id = id;
		}

		public static KeyDerivationFunction getById(final byte[] id) throws Exception {
			for (final KeyDerivationFunction keyDerivationFunction : KeyDerivationFunction.values()) {
				if (Arrays.equals(keyDerivationFunction.id, id)) {
					return keyDerivationFunction;
				}
			}
			throw new Exception("Invalid KeyDerivationFunction id: " + Utilities.toHexString(id));
		}
	}

	public enum OuterEncryptionAlgorithm {
		AES_128(Utilities.fromHexString("61ab05a1-9464-41c3-8d74-3a563df8dd35", true)),
		AES_256(Utilities.fromHexString("31c1f2e6-bf71-4350-be58-05216afc5aff", true)),
		CHACHA20(Utilities.fromHexString("d6038a2b-8b6f-4cb5-a524-339a31dbb59a", true)),
		TWOFISH(Utilities.fromHexString("ad68f29f-576f-4bb9-a36a-d47af965346c", true));

		private final byte[] id;

		public byte[] getId() {
			return id;
		}

		OuterEncryptionAlgorithm(final byte[] id) {
			this.id = id;
		}

		public static OuterEncryptionAlgorithm getById(final byte[] id) throws Exception {
			for (final OuterEncryptionAlgorithm outerEncryptionAlgorithm : OuterEncryptionAlgorithm.values()) {
				if (Arrays.equals(outerEncryptionAlgorithm.id, id)) {
					return outerEncryptionAlgorithm;
				}
			}
			throw new Exception("Invalid OuterEncryptionAlgorithm id: " + Utilities.toHexString(id));
		}
	}

	public enum InnerEncryptionAlgorithm {
		NONE(0),
		ARC4_VARIANT(1),
		SALSA20(2),
		CHACHA20(3);

		private final int id;

		public int getId() {
			return id;
		}

		InnerEncryptionAlgorithm(final int id) {
			this.id = id;
		}

		public static InnerEncryptionAlgorithm getById(final int id) throws Exception {
			for (final InnerEncryptionAlgorithm innerEncryptionAlgorithm : InnerEncryptionAlgorithm.values()) {
				if (innerEncryptionAlgorithm.id == id) {
					return innerEncryptionAlgorithm;
				}
			}
			throw new Exception("Invalid InnerEncryptionAlgorithm id: " + id);
		}
	}

	public enum PayloadBlockType {
		PAYLOAD(0x00),
		END_OF_PAYLOAD(0x01);

		private final int id;

		PayloadBlockType(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}
	}
}
