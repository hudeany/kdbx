package de.soderer.utilities.kdbx;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Access to the KeePass "Windows user account" key (compatible with KeePass 2.x, KeePassLib.Keys.KcpUserAccount).
 * <p>
 * KeePass stores 64 random bytes in "%APPDATA%\KeePass\ProtectedUserKey.bin", encrypted with Windows DPAPI
 * (scope CurrentUser) and a fixed KeePass entropy. The composite key of a database uses SHA-256 of the decrypted bytes.
 * <p>
 * DPAPI is called via the Windows PowerShell 5.1 that ships with Windows, so no native library (JNA) is needed.
 * Secret data is passed via stdin/stdout only, never via command line arguments.
 * <p>
 * Important: The key is bound to the Windows user account (its DPAPI master key). If the account is lost
 * (reinstallation, other machine without roaming profile, password reset by an administrator), the database cannot be opened anymore.
 * Backing up the decrypted key ({@link #load()}) is the only protection against that.
 */
public class WindowsUserAccountKey {
	/**
	 * Constant DPAPI entropy used by KeePass (KcpUserAccount.m_pbEntropy).
	 */
	private static final byte[] KEEPASS_ENTROPY = new byte[] {
			(byte) 0xDE, (byte) 0x13, (byte) 0x5B, (byte) 0x5F, (byte) 0x18, (byte) 0xA3, (byte) 0x46, (byte) 0x70,
			(byte) 0xB2, (byte) 0x57, (byte) 0x24, (byte) 0x29, (byte) 0x69, (byte) 0x88, (byte) 0x98, (byte) 0xE6
	};

	/**
	 * File name used by KeePass for the protected user key.
	 */
	public static final String USER_KEY_FILE_NAME = "ProtectedUserKey.bin";

	/**
	 * Size of a newly created user key (same as KeePass).
	 */
	private static final int NEW_USER_KEY_LENGTH = 64;

	/**
	 * Maximum time to wait for PowerShell.
	 */
	private static final long POWERSHELL_TIMEOUT_SECONDS = 60;

	private WindowsUserAccountKey() {
		// Utility class
	}

	/**
	 * Returns the default location of KeePass' protected user key file: "%APPDATA%\KeePass\ProtectedUserKey.bin".
	 *
	 * @return the default user key file
	 * @throws Exception if not running on Windows or APPDATA is not set
	 */
	public static File getDefaultUserKeyFile() throws Exception {
		checkWindows();
		final String appData = System.getenv("APPDATA");
		if (appData == null || appData.isBlank()) {
			throw new Exception("Environment variable APPDATA is not set");
		}
		return new File(new File(appData, "KeePass"), USER_KEY_FILE_NAME);
	}

	/**
	 * Loads and decrypts the Windows user account key of the currently logged on user from the default KeePass location.
	 *
	 * @return the unprotected user key (caller should clear it after use)
	 * @throws Exception if the key file does not exist or cannot be decrypted
	 */
	public static byte[] load() throws Exception {
		return load(getDefaultUserKeyFile());
	}

	/**
	 * Loads and decrypts a protected user key file for the currently logged on Windows user.
	 *
	 * @param protectedUserKeyFile the "ProtectedUserKey.bin" file
	 * @return the unprotected user key (caller should clear it after use)
	 * @throws Exception if the key file does not exist or cannot be decrypted
	 */
	public static byte[] load(final File protectedUserKeyFile) throws Exception {
		if (!protectedUserKeyFile.isFile()) {
			throw new Exception("Windows user account key file does not exist: " + protectedUserKeyFile.getAbsolutePath());
		}
		return unprotect(Files.readAllBytes(protectedUserKeyFile.toPath()));
	}

	/**
	 * Loads the Windows user account key of the currently logged on user or creates a new one, if none exists yet
	 * (like KeePass does when a database with "Windows user account" is created).
	 * An existing key file is never overwritten.
	 *
	 * @return the unprotected user key (caller should clear it after use)
	 * @throws Exception if the key cannot be read, decrypted, created or stored
	 */
	public static byte[] loadOrCreate() throws Exception {
		final File userKeyFile = getDefaultUserKeyFile();
		if (userKeyFile.exists()) {
			return load(userKeyFile);
		}

		final byte[] newKey = new byte[NEW_USER_KEY_LENGTH];
		new SecureRandom().nextBytes(newKey);
		final byte[] protectedKey = protect(newKey);

		final File parentDirectory = userKeyFile.getParentFile();
		if (!parentDirectory.isDirectory() && !parentDirectory.mkdirs()) {
			throw new IOException("Cannot create directory: " + parentDirectory.getAbsolutePath());
		}
		// CREATE_NEW: never overwrite a key file created concurrently (e.g. by KeePass)
		Files.write(userKeyFile.toPath(), protectedKey, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

		// Verify the stored key before anyone encrypts a database with it
		final byte[] verifiedKey = load(userKeyFile);
		if (!Arrays.equals(newKey, verifiedKey)) {
			Arrays.fill(newKey, (byte) 0);
			Arrays.fill(verifiedKey, (byte) 0);
			throw new Exception("Verification of the stored Windows user account key failed");
		}
		Arrays.fill(verifiedKey, (byte) 0);
		return newKey;
	}

	/**
	 * Decrypts data with Windows DPAPI (scope CurrentUser) and the KeePass entropy.
	 *
	 * @param protectedData the DPAPI encrypted data
	 * @return the decrypted data
	 * @throws Exception if decryption fails (e.g. other Windows user or not running on Windows)
	 */
	public static byte[] unprotect(final byte[] protectedData) throws Exception {
		return runDpapi("Unprotect", protectedData);
	}

	/**
	 * Encrypts data with Windows DPAPI (scope CurrentUser) and the KeePass entropy.
	 *
	 * @param data the data to encrypt
	 * @return the DPAPI encrypted data
	 * @throws Exception if encryption fails or not running on Windows
	 */
	public static byte[] protect(final byte[] data) throws Exception {
		return runDpapi("Protect", data);
	}

	private static byte[] runDpapi(final String method, final byte[] inputData) throws Exception {
		checkWindows();

		// Input and output are transferred base64 encoded via stdin/stdout, so no secret appears on the command line
		final String script = "$ErrorActionPreference = 'Stop';"
				+ "Add-Type -AssemblyName System.Security;"
				+ "$data = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim());"
				+ "$entropy = [Convert]::FromBase64String('" + Base64.getEncoder().encodeToString(KEEPASS_ENTROPY) + "');"
				+ "$result = [System.Security.Cryptography.ProtectedData]::" + method + "($data, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser);"
				+ "[Console]::Out.Write([Convert]::ToBase64String($result));"
				+ "[Array]::Clear($data, 0, $data.Length);"
				+ "[Array]::Clear($result, 0, $result.Length);";
		final String encodedScript = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_16LE));

		final ProcessBuilder processBuilder = new ProcessBuilder(getPowerShellPath(), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedScript);
		final Process process = processBuilder.start();

		final ByteCollector errorCollector = new ByteCollector(process.getErrorStream());
		errorCollector.start();

		final byte[] inputBase64 = Base64.getEncoder().encode(inputData);
		try (OutputStream processInput = process.getOutputStream()) {
			processInput.write(inputBase64);
		} finally {
			Arrays.fill(inputBase64, (byte) 0);
		}

		final byte[] outputBase64;
		try (InputStream processOutput = process.getInputStream()) {
			outputBase64 = processOutput.readAllBytes();
		}

		if (!process.waitFor(POWERSHELL_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
			process.destroyForcibly();
			Arrays.fill(outputBase64, (byte) 0);
			throw new Exception("Timeout of PowerShell DPAPI call");
		}
		errorCollector.join(TimeUnit.SECONDS.toMillis(5));

		if (process.exitValue() != 0) {
			Arrays.fill(outputBase64, (byte) 0);
			final String errorText = new String(errorCollector.getData(), StandardCharsets.UTF_8).trim();
			throw new Exception("DPAPI " + method + " failed (exit code " + process.exitValue() + ")" + (errorText.isEmpty() ? "" : ": " + errorText));
		}

		try {
			// MIME decoder ignores line breaks and other characters outside of the base64 alphabet
			return Base64.getMimeDecoder().decode(outputBase64);
		} finally {
			Arrays.fill(outputBase64, (byte) 0);
		}
	}

	/**
	 * Uses the absolute path of Windows PowerShell to prevent execution of a "powershell.exe" found earlier in PATH.
	 */
	private static String getPowerShellPath() {
		String systemRoot = System.getenv("SystemRoot");
		if (systemRoot == null || systemRoot.isBlank()) {
			systemRoot = "C:\\Windows";
		}
		return systemRoot + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	}

	private static void checkWindows() throws Exception {
		final String osName = System.getProperty("os.name", "");
		if (!osName.toLowerCase().startsWith("windows")) {
			throw new Exception("Windows user account credentials are only available on Windows (current OS: " + osName + ")");
		}
	}

	/**
	 * Reads a stream completely in a separate thread to prevent blocking of the process on a full pipe buffer.
	 */
	private static class ByteCollector extends Thread {
		private final InputStream inputStream;
		private volatile byte[] data = new byte[0];

		ByteCollector(final InputStream inputStream) {
			this.inputStream = inputStream;
			setDaemon(true);
		}

		@Override
		public void run() {
			try (InputStream stream = inputStream) {
				data = stream.readAllBytes();
			} catch (@SuppressWarnings("unused") final IOException e) {
				// Error output is only used for diagnostics
			}
		}

		byte[] getData() {
			return data;
		}
	}
}
