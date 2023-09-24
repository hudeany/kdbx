# kdbx
Java Kdbx File Format Reader and Writer (KeePass2 file format)

Release 2.0.0:
- Binary Attachment support
- Improved internal header data storage

Release 1.0.0:
- KdbxWriter and -Reader for Dataversion 3.x && 4.x is now working and created kdbx files are read by the KeePass2 application without errors.

## Dependencies:
- JAVA 11
- Bouncy Castle Crypto Provider
    (current version "1.70", see: "https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on" for download)

## Supported encryption algorithms:
- AES 128
- AES 256
- Salsa20
- ChaCha20

## Supported KDF (Key Derivation Function) algorithms:
- AES_KDBX3
- AES_KDBX4
- ARGON2D
- ARGON2ID

## Supported credential types:
- Password only
- Password with keyfile (simple keyfile like txt or Kdbx keyfile version 1.00 and 2.0)
- Keyfile only (simple keyfile like txt or Kdbx keyfile version 1.00 and 2.0)
- NOT SUPPORTED: Windows user account

## Code examples
### KdbxReader example with simple password:
```java
try (KdbxReader kdbxReader = new KdbxReader(new FileInputStream("MyKeePassDatabase.kdbx"))) {
	final KdbxDatabase database = kdbxReader.readKdbxDatabase("MyPassword".toCharArray());
	System.out.println("Databasename: " + database.getMeta().getDatabaseName()));
	System.out.println("Number of groups on first level: " + database.getGroups().size());
	System.out.println("Groupname: " + database.getGroups().get(0).getName());
	System.out.println("Number of groups within other group: " + database.getGroups().get(0).getGroups().size());
	System.out.println("Groupname of deeper group: " + database.getGroups().get(0).getGroups().get(0).getName());
	System.out.println("Overall number of stored entries: " + database.getAllEntries().size());
	System.out.println("Username of entry: " + database.getEntryByUUID(database.getGroups().get(0).getEntries().get(0)).getUsername());
	System.out.println("Password of entry: " + database.getEntryByUUID(database.getGroups().get(0).getEntries().get(0)).getPassword());
	System.out.println("Password of special entry: " + database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
} catch (final Exception e) {
	e.printStackTrace();
}
```

### KdbxReader example with password and keyfile:
```java
try (KdbxReader kdbxReader = new KdbxReader(new FileInputStream("MyKeePassDatabase.kdbx"))) {
	final byte[] keyFileData = Utilities.toByteArray(new FileInputStream("MyKeePassKeyFile.keyx"));
	final KdbxCredentials credentials = new KdbxCredentials("MyPassword".toCharArray(), keyFileData);
	final KdbxDatabase database = kdbxReader.readKdbxDatabase(credentials);
	System.out.println("Overall number of stored entries: " + database.getAllEntries().size());
} catch (final Exception e) {
	e.printStackTrace();
}
```

### KdbxWriter example with simple password:
```java
KdbxDatabase database = new KdbxDatabase();
database.getMeta().setDatabaseName("MyDatabase");

final KdbxEntry kdbxEntry = new KdbxEntry();
kdbxEntry.setTitle("MyEntry");
kdbxEntry.setUrl("https://MyDomain");
kdbxEntry.setUsername("MyUsernameForThisEntry");
kdbxEntry.setPassword("MyPasswordForThisEntry");
database.getEntries().add(kdbxEntry);

// KDBX default data version v4
try (KdbxWriter kdbxWriter = new KdbxWriter(new FileOutputStream("MyKeePassDatabase.kdbx"))) {
	kdbxWriter.writeKdbxDatabase(database, "MyDatabasePassword".toCharArray());
} catch (final Exception e) {
	e.printStackTrace();
}

try (KdbxReader kdbxReader = new KdbxReader(new FileInputStream("MyKeePassDatabase.kdbx"))) {
	database = kdbxReader.readKdbxDatabase("MyDatabasePassword".toCharArray());
	System.out.println(database.getHeaderFormat().getDataFormatVersion().toString());
	System.out.println(database.getMeta().getDatabaseName());
	System.out.println(database.getAllEntries().size());
	System.out.println(database.getEntries().get(0).getTitle());
	System.out.println(database.getEntries().get(0).getUrl());
	System.out.println(database.getEntries().get(0).getUsername());
	System.out.println(database.getEntries().get(0).getPassword());
} catch (final Exception e) {
	e.printStackTrace();
}

// KDBX data version v3
try (KdbxWriter kdbxWriter = new KdbxWriter(new FileOutputStream("MyKeePassDatabase_v3.kdbx"))) {
	KdbxHeaderFormat headerFormat = new KdbxHeaderFormat3();
	headerFormat.setInnerEncryptionAlgorithm(InnerEncryptionAlgorithm.SALSA20);
	kdbxWriter.writeKdbxDatabase(database, headerFormat, "MyDatabasePassword".toCharArray());
} catch (final Exception e) {
	e.printStackTrace();
}

try (KdbxReader kdbxReader = new KdbxReader(new FileInputStream("MyKeePassDatabase_v3.kdbx"))) {
	database = kdbxReader.readKdbxDatabase("MyDatabasePassword".toCharArray());
	System.out.println(database.getHeaderFormat().getDataFormatVersion().toString());
	System.out.println(database.getMeta().getDatabaseName());
	System.out.println(database.getAllEntries().size());
	System.out.println(database.getEntries().get(0).getTitle());
	System.out.println(database.getEntries().get(0).getUrl());
	System.out.println(database.getEntries().get(0).getUsername());
	System.out.println(database.getEntries().get(0).getPassword());
} catch (final Exception e) {
	e.printStackTrace();
}
```

## Maven2 repository
This library is also available via Maven2 repository
 
	<repositories>
		<repository>
			<id>de.soderer</id>
			<url>http://soderer.de/maven2</url>
		</repository>
	</repositories>

	<dependency>
		<groupId>de.soderer</groupId>
		<artifactId>kdbx</artifactId>
		<version>RELEASE</version>
	</dependency>
