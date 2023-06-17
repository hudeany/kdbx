# kdbx
Kdbx File Format Reader and Writer (KeePass2 file format)

By now only KdbxReader is working
KdbxWriter is still missing, but will come in near time.

KdbxReader example with simple password:
```java
try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("MyKeePassDatabase.kdbx"))) {
  final KdbxDatabase database = kdbxReader.readKdbxDatabase("MyPassword".toCharArray());
  System.out.println(database.getMeta().getDatabaseName()));
  System.out.println(database.getGroups().size());
  System.out.println(database.getGroups().get(0).getName());
  System.out.println(database.getGroups().get(0).getGroups().size());
  System.out.println(database.getGroups().get(0).getGroups().get(0).getName());
  System.out.println(database.getAllEntries().size());
  System.out.println(database.getEntryByUUID(database.getGroups().get(0).getEntries().get(0)).getUsername());
  System.out.println(database.getEntryByUUID(database.getGroups().get(0).getEntries().get(0)).getPassword());
  System.out.println(database.getEntryByUUID(database.getAllEntries().get(0)).getPassword());
  System.out.println(database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
} catch (final Exception e) {
  e.printStackTrace();
  Assert.fail(e.getMessage());
}
```

KdbxReader example with password and keyfile:
```java
try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("MyKeePassDatabase.kdbx"))) {
  final byte[] keyFileData = IoUtilities.toByteArray(getClass().getClassLoader().getResourceAsStream("MyKeePassKeyFile.keyx"));
	final KdbxCredentials credentials = new KdbxCredentials("MyPassword".toCharArray(), keyFileData);
	final KdbxDatabase database = kdbxReader.readKdbxDatabase(credentials);
  System.out.println(database.getAllEntries().size());
} catch (final Exception e) {
  e.printStackTrace();
  Assert.fail(e.getMessage());
}
```
