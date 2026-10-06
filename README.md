# kdbx

[![Maven Central](https://img.shields.io/maven-central/v/de.soderer/kdbx?label=Maven%20Central)](https://central.sonatype.com/artifact/de.soderer/kdbx)

**Java reader and writer for KeePass 2 database files (KDBX format)**

Read and write KeePass databases in data format versions 3.x and 4.x directly from Java, including groups, entries, history, attachments, custom fields and auto-type settings. Files written by this library can be opened with KeePass 2 and other KDBX compatible applications.

## Features

- Reading of KDBX 3.x and 4.x files, writing of KDBX 3.1 and 4.x files
- Groups and entries in any nesting depth, including entries on root level
- Entry history, attachments (also of history entries) and custom fields
- Protected values: custom fields read as protected stay protected when written again
- Auto-type settings, custom icons, custom data, deleted objects and meta data
- Fresh random master seed, IV, KDF salt and inner stream key for every write
- `MasterKeyChanged` is only updated when the credentials have actually changed
- Hardened against crafted files: XXE protection, limits for KDF parameters and block sizes, verification of all HMAC blocks (detects truncated files)

## Requirements

- Java 11 or higher
- [Bouncy Castle](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on) (`bcprov-jdk18on`), used for Argon2, Salsa20 and the inner ChaCha20 stream

## Maven

This library is available on [Maven Central](https://central.sonatype.com/artifact/de.soderer/kdbx). The current version is shown in the badge above.

```xml
<dependency>
	<groupId>de.soderer</groupId>
	<artifactId>kdbx</artifactId>
	<version>x.y.z</version>
</dependency>
```

Bouncy Castle (`org.bouncycastle:bcprov-jdk18on`) is needed at runtime.

## Supported algorithms

| Purpose | Algorithms |
|---|---|
| Payload encryption | AES-256 (KDBX 3.x and 4.x), ChaCha20 (KDBX 4.x) |
| Protection of values | Salsa20, ChaCha20 |
| Key derivation (KDF) | AES-KDF (KDBX 3.x and 4.x), Argon2d, Argon2id |
| Compression | GZip or none |

Not supported: Twofish (KeePass plugin), ArcFour inner stream.

## Supported credentials

- Password
- Key file
- Password and key file

Key file formats are detected in the same order as KeePass and KeePassXC do:

1. XML key file version 1.0 or 2.0 (`.keyx` / `.key`), with verification of the integrity hash of version 2.0
2. Exactly 32 bytes, used directly as key
3. Exactly 64 hexadecimal characters
4. Any other file content, hashed with SHA-256

Not supported: Windows user account.

## Usage

### Reading a database with a password

```java
try (KdbxReader kdbxReader = new KdbxReader(new FileInputStream("MyKeePassDatabase.kdbx"))) {
	final KdbxDatabase database = kdbxReader.readKdbxDatabase("MyPassword".toCharArray());

	System.out.println("Database name: " + database.getMeta().getDatabaseName());
	System.out.println("Number of top level groups: " + database.getGroups().size());
	System.out.println("Number of all entries: " + database.getAllEntries().size());

	final KdbxGroup group = database.getGroups().get(0);
	System.out.println("Group name: " + group.getName());

	final KdbxEntry entry = group.getEntries().get(0);
	System.out.println("Username: " + entry.getUsername());
	System.out.println("Password: " + entry.getPassword());

	final KdbxEntry specialEntry = database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA"));
	System.out.println("Password of special entry: " + specialEntry.getPassword());
}
```

### Reading a database with password and key file

```java
final byte[] keyFileData = Files.readAllBytes(Paths.get("MyKeePassKeyFile.keyx"));
final KdbxCredentials credentials = new KdbxCredentials("MyPassword".toCharArray(), keyFileData);

try (KdbxReader kdbxReader = new KdbxReader(new FileInputStream("MyKeePassDatabase.kdbx"))) {
	final KdbxDatabase database = kdbxReader.readKdbxDatabase(credentials);
	System.out.println("Number of all entries: " + database.getAllEntries().size());
}
```

### Creating and writing a database (KDBX 4)

```java
final KdbxDatabase database = new KdbxDatabase();
database.getMeta().setDatabaseName("MyDatabase");

final KdbxGroup group = new KdbxGroup().withName("Internet");
database.getGroups().add(group);

final KdbxEntry entry = new KdbxEntry()
	.withTitle("MyEntry")
	.withUrl("https://example.com")
	.withUsername("MyUsername")
	.withPassword("MyPassword");
group.getEntries().add(entry);

// Custom field, which is stored as protected value
entry.setItem("PIN", "1234");
entry.setItemProtected("PIN", true);

// Attachment
entry.getBinaries().add(new KdbxEntryBinary().withKey("notes.txt").withData("Some text".getBytes(StandardCharsets.UTF_8)));

try (KdbxWriter kdbxWriter = new KdbxWriter(new FileOutputStream("MyKeePassDatabase.kdbx"))) {
	kdbxWriter.writeKdbxDatabase(database, "MyDatabasePassword".toCharArray());
}
```

### Writing in data format KDBX 3.1

```java
final KdbxHeaderFormat3 headerFormat = new KdbxHeaderFormat3();
headerFormat.setInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.SALSA20);

try (KdbxWriter kdbxWriter = new KdbxWriter(new FileOutputStream("MyKeePassDatabase_v3.kdbx"))) {
	kdbxWriter.writeKdbxDatabase(database, headerFormat, "MyDatabasePassword".toCharArray());
}
```

### Choosing encryption and key derivation (KDBX 4)

```java
final KdbxHeaderFormat4 headerFormat = new KdbxHeaderFormat4()
	.withOuterEncryptionAlgorithm(OuterEncryptionAlgorithm.CHACHA20)
	.withKeyDerivationFunctionInfo(new KeyDerivationFunctionInfoArgon()
		.withType(KeyDerivationFunctionInfoArgon.Argon2Type.Argon2_ID)
		.withIterations(3)
		.withMemoryInBytes(64 * 1024 * 1024)
		.withParallelism(2));

try (KdbxWriter kdbxWriter = new KdbxWriter(new FileOutputStream("MyKeePassDatabase.kdbx"))) {
	kdbxWriter.writeKdbxDatabase(database, headerFormat, new KdbxCredentials("MyDatabasePassword".toCharArray()));
}
```

### Notes

- `KdbxReader` and `KdbxWriter` close the given stream.
- A database read from a file can be changed and written again, also several times. Attachments stay available in the entries.
- With `kdbxReader.setStrictMode(true)` unknown XML elements and a missing KDBX 3.x header hash are rejected instead of ignored.
