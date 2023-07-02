# kdbx
Java Kdbx File Format Reader and Writer (KeePass2 file format)

## Dependencies:
- JAVA 8
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

By now only KdbxReader is working
KdbxWriter for Dataversion 4.x is now working
KdbxWriter for Dataversion 3.x will come in near future

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
final KdbxEntry kdbxEntry = new KdbxEntry();
kdbxEntry.setUsername("MyUsername");
kdbxEntry.setPassword("MyPassword");
database.getEntries().add(kdbxEntry);

try (KdbxWriter kdbxWriter = new KdbxWriter(new FileOutputStream("MyKeePassDatabase.kdbx"))) {
  kdbxWriter.writeKdbxDatabase(database, "MyPassword".toCharArray());
} catch (final Exception e) {
  e.printStackTrace();
}
```
