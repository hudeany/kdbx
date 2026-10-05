package de.soderer.utilities.kdbx;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.utilities.BOM;
import de.soderer.utilities.kdbx.utilities.IoUtilities;

@SuppressWarnings("static-method")
public class KdbxReaderTest {
	@Test
	public void test_AES256_AESKDF_GZIP() {
		KdbxDatabase database = null;

		try (InputStream resourceAsStream = getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF.kdbx");
				KdbxReader kdbxReader = new KdbxReader(resourceAsStream)) {
			kdbxReader.setStrictMode(true);
			database = kdbxReader.readKdbxDatabase("Äbc123@".toCharArray());

			assertEquals("4.1.0", database.getHeaderFormat().getDataFormatVersion().toString());

			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		try (KdbxWriter kdbxWriter = new KdbxWriter(outputStream)) {
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			if (database == null) {
				fail("Databse is null");
				throw new RuntimeException();
			}
			kdbxWriter.writeKdbxDatabase(database, database.getHeaderFormat(), credentials);
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		assertTrue(outputStream.size() > 0);

		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(outputStream.toByteArray()))) {
			kdbxReader.setStrictMode(true);
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			database = kdbxReader.readKdbxDatabase(credentials);

			assertEquals("4.1.0", database.getHeaderFormat().getDataFormatVersion().toString());

			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_ChaCha20_Argon2d_GZIP() {
		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_ChaCha20_Argon2d.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final KdbxDatabase database = kdbxReader.readKdbxDatabase("Äbc123@".toCharArray());
			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_ChaCha20_Argon2id_GZIP() {
		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_ChaCha20_Argon2id.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final KdbxDatabase database = kdbxReader.readKdbxDatabase("Äbc123@".toCharArray());
			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}
	@Test
	public void test_AES256_AESKDF_NoZIP() {
		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_NoZip.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final KdbxDatabase database = kdbxReader.readKdbxDatabase("Äbc123@".toCharArray());
			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_AES256_AESKDF_PwdAndTxtKeyFile_GZIP() {
		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_PwdTxtKeyFile.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final byte[] keyFileData = IoUtilities.toByteArray(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_PwdTxtKeyFile.txt"));
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray(), keyFileData);
			final KdbxDatabase database = kdbxReader.readKdbxDatabase(credentials);
			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_AES256_AESKDF_PwdAndKeyFileV1_GZIP() {
		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_PwdKeyFileV1.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final byte[] keyFileData = IoUtilities.toByteArray(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_PwdKeyFileV1.keyx"));
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray(), keyFileData);
			final KdbxDatabase database = kdbxReader.readKdbxDatabase(credentials);
			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_AES256_AESKDF_PwdAndKeyFileV2_GZIP() {
		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_PwdKeyFileV2.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final byte[] keyFileData = IoUtilities.toByteArray(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_PwdKeyFileV2.keyx"));
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray(), keyFileData);
			final KdbxDatabase database = kdbxReader.readKdbxDatabase(credentials);
			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_AES256_AESKDF_KeyFile() {
		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_KeyFile.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final byte[] keyFileData = IoUtilities.toByteArray(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_KeyFile.keyx"));
			final KdbxCredentials credentials = new KdbxCredentials(keyFileData);
			final KdbxDatabase database = kdbxReader.readKdbxDatabase(credentials);
			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertEquals("Test Pässword #2", database.getEntryByUUID(KdbxUUID.fromHex("FE30E9479289424F81439234970F59AA")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_v3() {
		KdbxDatabase database = null;

		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v3/Database_Salsa20.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			database = kdbxReader.readKdbxDatabase(credentials);

			assertEquals("3.1.0", database.getHeaderFormat().getDataFormatVersion().toString());

			assertEquals(null, database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Test Group", database.getGroups().get(0).getName());

			assertEquals(1, database.getGroups().get(0).getGroups().size());
			assertEquals("RecycleBin", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(1, database.getAllEntries().size());
			assertEquals("Test Pässword", database.getEntryByUUID(KdbxUUID.fromHex("9AA8B51CB14AEE4FB3F4DB2C86B8E552")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		try (KdbxWriter kdbxWriter = new KdbxWriter(outputStream)) {
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			if (database == null) {
				fail("Databse is null");
				throw new RuntimeException();
			}
			kdbxWriter.writeKdbxDatabase(database, database.getHeaderFormat(), credentials);
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		assertTrue(outputStream.size() > 0);

		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(outputStream.toByteArray()))) {
			kdbxReader.setStrictMode(true);
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			database = kdbxReader.readKdbxDatabase(credentials);

			assertEquals("3.1.0", database.getHeaderFormat().getDataFormatVersion().toString());

			assertEquals(null, database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Test Group", database.getGroups().get(0).getName());

			assertEquals(1, database.getGroups().get(0).getGroups().size());
			assertEquals("RecycleBin", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(1, database.getAllEntries().size());
			assertEquals("Test Pässword", database.getEntryByUUID(KdbxUUID.fromHex("9AA8B51CB14AEE4FB3F4DB2C86B8E552")).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_v3_withBinaries() {
		KdbxDatabase database = null;

		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v3/Database_Salsa20_bin.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			database = kdbxReader.readKdbxDatabase(credentials);

			assertEquals("3.1.0", database.getHeaderFormat().getDataFormatVersion().toString());

			assertEquals(null, database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Test Group", database.getGroups().get(0).getName());

			assertEquals(1, database.getGroups().get(0).getGroups().size());
			assertEquals("RecycleBin", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Pässword", database.getEntryByUUID(KdbxUUID.fromHex("9AA8B51CB14AEE4FB3F4DB2C86B8E552")).getPassword());
			assertArrayEquals((BOM.BOM_UTF_8_CHAR + "Binary Öne").getBytes(StandardCharsets.UTF_8), database.getEntryByUUID(KdbxUUID.fromHex("9AA8B51CB14AEE4FB3F4DB2C86B8E552")).getBinaries().get(0).getData());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		try (KdbxWriter kdbxWriter = new KdbxWriter(outputStream)) {
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			if (database == null) {
				fail("Databse is null");
				throw new RuntimeException();
			}
			kdbxWriter.writeKdbxDatabase(database, database.getHeaderFormat(), credentials);
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		assertTrue(outputStream.size() > 0);

		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(outputStream.toByteArray()))) {
			kdbxReader.setStrictMode(true);
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			database = kdbxReader.readKdbxDatabase(credentials);

			assertEquals("3.1.0", database.getHeaderFormat().getDataFormatVersion().toString());

			assertEquals(null, database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Test Group", database.getGroups().get(0).getName());

			assertEquals(1, database.getGroups().get(0).getGroups().size());
			assertEquals("RecycleBin", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Pässword", database.getEntryByUUID(KdbxUUID.fromHex("9AA8B51CB14AEE4FB3F4DB2C86B8E552")).getPassword());
			assertArrayEquals((BOM.BOM_UTF_8_CHAR + "Binary Öne").getBytes(StandardCharsets.UTF_8), database.getEntryByUUID(KdbxUUID.fromHex("9AA8B51CB14AEE4FB3F4DB2C86B8E552")).getBinaries().get(0).getData());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_v4_withBinaries() {
		KdbxDatabase database = null;

		try (KdbxReader kdbxReader = new KdbxReader(getClass().getClassLoader().getResourceAsStream("kdbx/v4/Database_AES256_AES-KDF_bin.kdbx"))) {
			kdbxReader.setStrictMode(true);
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			database = kdbxReader.readKdbxDatabase(credentials);

			assertEquals("4.1.0", database.getHeaderFormat().getDataFormatVersion().toString());

			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertArrayEquals((BOM.BOM_UTF_8_CHAR + "Binary Öne").getBytes(StandardCharsets.UTF_8), database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getBinaries().get(0).getData());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		try (KdbxWriter kdbxWriter = new KdbxWriter(outputStream)) {
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			if (database == null) {
				fail("Databse is null");
				throw new RuntimeException();
			}
			kdbxWriter.writeKdbxDatabase(database, database.getHeaderFormat(), credentials);
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		assertTrue(outputStream.size() > 0);

		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(outputStream.toByteArray()))) {
			kdbxReader.setStrictMode(true);
			final KdbxCredentials credentials = new KdbxCredentials("Äbc123@".toCharArray());
			database = kdbxReader.readKdbxDatabase(credentials);

			assertEquals("4.1.0", database.getHeaderFormat().getDataFormatVersion().toString());

			assertEquals("Test Database", database.getMeta().getDatabaseName());

			assertEquals(1, database.getGroups().size());
			assertEquals("Database", database.getGroups().get(0).getName());

			assertEquals(6, database.getGroups().get(0).getGroups().size());
			assertEquals("General", database.getGroups().get(0).getGroups().get(0).getName());

			assertEquals(2, database.getAllEntries().size());
			assertEquals("Test Password", database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getPassword());
			assertArrayEquals((BOM.BOM_UTF_8_CHAR + "Binary Öne").getBytes(StandardCharsets.UTF_8), database.getEntryByUUID(KdbxUUID.fromHex("957C944A05D8E9489787D94EF07C8319")).getBinaries().get(0).getData());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void test_create_new_v4_database() {
		KdbxDatabase database = new KdbxDatabase();
		database.getMeta().setDatabaseName("MyDatabase");
		final KdbxEntry kdbxEntry = new KdbxEntry();
		kdbxEntry.setTitle("MyEntry");
		kdbxEntry.setUrl("https://MyDomain");
		kdbxEntry.setUsername("MyUsernameForThisEntry");
		kdbxEntry.setPassword("MyPasswordForThisEntry");
		database.getEntries().add(kdbxEntry);

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (KdbxWriter kdbxWriter = new KdbxWriter(outputStream)) {
			kdbxWriter.writeKdbxDatabase(database, "MyDatabasePassword".toCharArray());
		} catch (final Exception e) {
			e.printStackTrace();
		}

		assertTrue(outputStream.size() > 0);

		try (KdbxReader kdbxReader = new KdbxReader(new ByteArrayInputStream(outputStream.toByteArray()))) {
			kdbxReader.setStrictMode(true);
			final KdbxCredentials credentials = new KdbxCredentials("MyDatabasePassword".toCharArray());
			database = kdbxReader.readKdbxDatabase(credentials);
			assertEquals("4.1.0", database.getHeaderFormat().getDataFormatVersion().toString());
			assertEquals("MyDatabase", database.getMeta().getDatabaseName());
			assertEquals(1, database.getAllEntries().size());
			assertEquals("MyEntry", database.getEntries().get(0).getTitle());
			assertEquals("https://MyDomain", database.getEntries().get(0).getUrl());
			assertEquals("MyUsernameForThisEntry", database.getEntries().get(0).getUsername());
			assertEquals("MyPasswordForThisEntry", database.getEntries().get(0).getPassword());
		} catch (final Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}
}
