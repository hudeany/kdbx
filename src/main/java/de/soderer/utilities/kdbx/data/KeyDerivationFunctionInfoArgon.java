package de.soderer.utilities.kdbx.data;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.Argon2Parameters;

import de.soderer.utilities.kdbx.data.KdbxConstants.KeyDerivationFunction;
import de.soderer.utilities.kdbx.utilities.VariantDictionary;
import de.soderer.utilities.kdbx.utilities.VariantDictionaryEntry;

/**
 * Argon2 key derivation configuration (Argon2d or Argon2id) with limits against excessive resource usage by crafted files.
 */
public class KeyDerivationFunctionInfoArgon implements KeyDerivationFunctionInfo {
	/**
	 * Argon2 variants.
	 */
	public enum Argon2Type {
		/**
		 * Argon2d, default of KeePass.
		 */
		Argon2_D(Argon2Parameters.ARGON2_d),
		/**
		 * Argon2id.
		 */
		Argon2_ID(Argon2Parameters.ARGON2_id);

		/**
		 * Type id of the Argon2 implementation.
		 */
		private final int argon2TypeID;

		/**
		 * Creates the constant.
		 *
		 * @param argon2TypeID type id of the Argon2 implementation
		 */
		Argon2Type(final int argon2TypeID) {
			this.argon2TypeID = argon2TypeID;
		}

		/**
		 * Returns the type id of the Argon2 implementation.
		 *
		 * @return the type id
		 */
		public int getArgon2TypeID() {
			return argon2TypeID;
		}
	}

	/**
	 * Argon2 variant.
	 */
	private Argon2Type type = Argon2Type.Argon2_D;
	/**
	 * Number of iterations.
	 */
	private int iterations = 2;
	/**
	 * Memory size in bytes.
	 */
	private long memoryInBytes = 64 * 1024 * 1024;
	/**
	 * Parallelism (number of lanes).
	 */
	private int parallelism = 2;
	/**
	 * Random salt or null to generate one for the next write.
	 */
	private byte[] salt;
	/**
	 * Argon2 version (0x10 or 0x13).
	 */
	private int version = 19;

	/**
	 * Creates an Argon2d configuration with the default values of KeePass: 2 iterations, 64 MiB memory, parallelism 2, version 0x13.
	 */
	public KeyDerivationFunctionInfoArgon() {
		// nothing to do
	}

	/**
	 * Sanity upper bounds for Argon2 parameters, to protect against maliciously crafted KDBX files
	 * that specify excessive values in order to force resource exhaustion (Denial of Service) during
	 * key derivation, which happens before the file's header integrity/authenticity can be verified.
	 * These limits are generous compared to any reasonable real-world KeePass configuration.
	 */
	private static final int MAX_ITERATIONS = 1_000;
	/**
	 * Maximum accepted memory size, to protect against crafted files.
	 */
	private static final long MAX_MEMORY_IN_BYTES = 2L * 1024 * 1024 * 1024; // 2 GB
	/**
	 * Maximum accepted parallelism, to protect against crafted files.
	 */
	private static final int MAX_PARALLELISM = 64;

	/**
	 * Returns the Argon2 variant.
	 *
	 * @return the Argon2 variant
	 */
	public Argon2Type getType() {
		return type;
	}

	/**
	 * Sets the Argon2 variant.
	 *
	 * @param type the Argon2 variant
	 */
	public void setType(final Argon2Type type) {
		if (type == null) {
			this.type = Argon2Type.Argon2_D;
		} else {
			this.type = type;
		}
	}

	/**
	 * Sets the Argon2 variant and returns this object for method chaining.
	 *
	 * @param newType the Argon2 variant
	 * @return this object
	 */
	public KeyDerivationFunctionInfoArgon withType(final Argon2Type newType) {
		setType(newType);
		return this;
	}

	/**
	 * Returns the number of iterations.
	 *
	 * @return the number of iterations
	 */
	public int getIterations() {
		return iterations;
	}

	/**
	 * Sets the number of iterations.
	 *
	 * @param iterations the number of iterations
	 */
	public void setIterations(final int iterations) {
		if (iterations <= 0) {
			throw new IllegalArgumentException("Invalid Argon2 iterations value: " + iterations);
		} else if (iterations > MAX_ITERATIONS) {
			throw new IllegalArgumentException("Argon2 iterations value " + iterations + " exceeds maximum allowed value of " + MAX_ITERATIONS);
		}
		this.iterations = iterations;
	}

	/**
	 * Sets the number of iterations and returns this object for method chaining.
	 *
	 * @param newIterations the number of iterations
	 * @return this object
	 */
	public KeyDerivationFunctionInfoArgon withIterations(final int newIterations) {
		setIterations(newIterations);
		return this;
	}

	/**
	 * Returns the memory size in bytes.
	 *
	 * @return the memory size in bytes
	 */
	public long getMemoryInBytes() {
		return memoryInBytes;
	}

	/**
	 * Sets the memory size in bytes.
	 *
	 * @param memoryInBytes the memory size in bytes
	 */
	public void setMemoryInBytes(final long memoryInBytes) {
		if (memoryInBytes <= 0) {
			throw new IllegalArgumentException("Invalid Argon2 memory value: " + memoryInBytes);
		} else if (memoryInBytes > MAX_MEMORY_IN_BYTES) {
			throw new IllegalArgumentException("Argon2 memory value " + memoryInBytes + " exceeds maximum allowed value of " + MAX_MEMORY_IN_BYTES + " bytes");
		}
		this.memoryInBytes = memoryInBytes;
	}

	/**
	 * Sets the memory size in bytes and returns this object for method chaining.
	 *
	 * @param newMemoryInBytes the memory size in bytes
	 * @return this object
	 */
	public KeyDerivationFunctionInfoArgon withMemoryInBytes(final long newMemoryInBytes) {
		setMemoryInBytes(newMemoryInBytes);
		return this;
	}

	/**
	 * Returns the parallelism (number of lanes).
	 *
	 * @return the parallelism (number of lanes)
	 */
	public int getParallelism() {
		return parallelism;
	}

	/**
	 * Sets the parallelism (number of lanes).
	 *
	 * @param parallelism the parallelism (number of lanes)
	 */
	public void setParallelism(final int parallelism) {
		if (parallelism <= 0) {
			throw new IllegalArgumentException("Invalid Argon2 parallelism value: " + parallelism);
		} else if (parallelism > MAX_PARALLELISM) {
			throw new IllegalArgumentException("Argon2 parallelism value " + parallelism + " exceeds maximum allowed value of " + MAX_PARALLELISM);
		}
		this.parallelism = parallelism;
	}

	/**
	 * Sets the parallelism (number of lanes) and returns this object for method chaining.
	 *
	 * @param newParallelism the parallelism (number of lanes)
	 * @return this object
	 */
	public KeyDerivationFunctionInfoArgon withParallelism(final int newParallelism) {
		setParallelism(newParallelism);
		return this;
	}

	/**
	 * Returns the random salt or null to generate one for the next write.
	 *
	 * @return the random salt or null to generate one for the next write
	 */
	public byte[] getSalt() {
		return salt;
	}

	/**
	 * Sets the random salt or null to generate one for the next write.
	 *
	 * @param salt the random salt or null to generate one for the next write
	 */
	public void setSalt(final byte[] salt) {
		this.salt = salt;
	}

	/**
	 * Sets the random salt or null to generate one for the next write and returns this object for method chaining.
	 *
	 * @param newSalt the random salt or null to generate one for the next write
	 * @return this object
	 */
	public KeyDerivationFunctionInfoArgon withSalt(final byte[] newSalt) {
		setSalt(newSalt);
		return this;
	}

	/**
	 * Returns the Argon2 version (0x10 or 0x13).
	 *
	 * @return the Argon2 version (0x10 or 0x13)
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Sets the Argon2 version (0x10 or 0x13).
	 *
	 * @param version the Argon2 version (0x10 or 0x13)
	 */
	public void setVersion(final int version) {
		if (version != 0x10 && version != 0x13) {
			throw new IllegalArgumentException("Invalid Argon2 version: 0x" + Integer.toHexString(version) + " (supported: 0x10, 0x13)");
		}
		this.version = version;
	}

	/**
	 * Sets the Argon2 version (0x10 or 0x13) and returns this object for method chaining.
	 *
	 * @param newVersion the Argon2 version (0x10 or 0x13)
	 * @return this object
	 */
	public KeyDerivationFunctionInfoArgon withVersion(final int newVersion) {
		setVersion(newVersion);
		return this;
	}

	@Override
	public byte[] getKdfParamsBytes() throws Exception {
		final VariantDictionary variantDictionary = new VariantDictionary();
		if (type == Argon2Type.Argon2_D) {
			variantDictionary.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.ARGON2D.getId());
		} else {
			variantDictionary.put(VariantDictionary.KDF_UUID, VariantDictionaryEntry.Type.BYTE_ARRAY, KeyDerivationFunction.ARGON2ID.getId());
		}
		variantDictionary.put(VariantDictionary.KDF_ARGON2_VERSION, VariantDictionaryEntry.Type.UINT_32, version);
		variantDictionary.put(VariantDictionary.KDF_ARGON2_ITERATIONS, VariantDictionaryEntry.Type.UINT_64, (long) iterations);
		variantDictionary.put(VariantDictionary.KDF_ARGON2_MEMORY_IN_BYTES, VariantDictionaryEntry.Type.UINT_64, memoryInBytes);
		variantDictionary.put(VariantDictionary.KDF_ARGON2_PARALLELISM, VariantDictionaryEntry.Type.UINT_32, parallelism);
		if (salt == null) {
			salt = new byte[32];
			new SecureRandom().nextBytes(salt);
		}
		variantDictionary.put(VariantDictionary.KDF_ARGON2_SALT, VariantDictionaryEntry.Type.BYTE_ARRAY, salt);
		final ByteArrayOutputStream bufferStream = new ByteArrayOutputStream();
		variantDictionary.write(bufferStream);
		return bufferStream.toByteArray();
	}

	@Override
	public void setValues(final VariantDictionary variantDictionary) throws Exception {
		final KeyDerivationFunction keyDerivationFunction = KeyDerivationFunction.getById((byte[]) variantDictionary.get(VariantDictionary.KDF_UUID).getJavaValue());
		if (keyDerivationFunction == KeyDerivationFunction.ARGON2D) {
			setType(KeyDerivationFunctionInfoArgon.Argon2Type.Argon2_D);
		} else if (keyDerivationFunction == KeyDerivationFunction.ARGON2ID) {
			setType(KeyDerivationFunctionInfoArgon.Argon2Type.Argon2_ID);
		} else {
			throw new Exception("Invalid KeyDerivationFunction (KDF) for KeyDerivationFunctionInfoArgon: " + keyDerivationFunction);
		}
		// Iterations are stored as unsigned 64 bit value: check the full value before narrowing it to int
		final long iterationsValue = ((Number) getRequiredValue(variantDictionary, VariantDictionary.KDF_ARGON2_ITERATIONS)).longValue();
		if (iterationsValue <= 0 || iterationsValue > MAX_ITERATIONS) {
			throw new IllegalArgumentException("Invalid Argon2 iterations value: " + Long.toUnsignedString(iterationsValue));
		}
		setIterations((int) iterationsValue);
		setMemoryInBytes(((Number) getRequiredValue(variantDictionary, VariantDictionary.KDF_ARGON2_MEMORY_IN_BYTES)).longValue());
		setParallelism(((Number) getRequiredValue(variantDictionary, VariantDictionary.KDF_ARGON2_PARALLELISM)).intValue());
		setSalt((byte[]) getRequiredValue(variantDictionary, VariantDictionary.KDF_ARGON2_SALT));
		setVersion(((Number) getRequiredValue(variantDictionary, VariantDictionary.KDF_ARGON2_VERSION)).intValue());
	}

	/**
	 * Returns the value of a required parameter.
	 *
	 * @param variantDictionary the parameters
	 * @param key key of the parameter
	 * @return the Java value of the parameter
	 * @throws Exception if the parameter is missing
	 */
	private static Object getRequiredValue(final VariantDictionary variantDictionary, final String key) throws Exception {
		final VariantDictionaryEntry entry = variantDictionary.get(key);
		if (entry == null) {
			throw new Exception("Missing Argon2 KDF parameter '" + key + "'");
		}
		return entry.getJavaValue();
	}

	/**
	 * Sets the parameters from a VariantDictionary and returns this object for method chaining.
	 *
	 * @param newVariantDictionary the parameters
	 * @return this object
	 * @throws Exception if parameters are missing or invalid
	 */
	public KeyDerivationFunctionInfoArgon withValues(final VariantDictionary newVariantDictionary) throws Exception {
		setValues(newVariantDictionary);
		return this;
	}

	@Override
	public void resetCryptoKeys() {
		salt = null;
	}
}
