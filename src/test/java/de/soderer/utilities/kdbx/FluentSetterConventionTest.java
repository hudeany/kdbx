package de.soderer.utilities.kdbx;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteOrder;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import de.soderer.utilities.kdbx.data.KdbxBinary;
import de.soderer.utilities.kdbx.data.KdbxCustomDataItem;
import de.soderer.utilities.kdbx.data.KdbxEntry;
import de.soderer.utilities.kdbx.data.KdbxEntryBinary;
import de.soderer.utilities.kdbx.data.KdbxGroup;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat3;
import de.soderer.utilities.kdbx.data.KdbxHeaderFormat4;
import de.soderer.utilities.kdbx.data.KdbxMemoryProtection;
import de.soderer.utilities.kdbx.data.KdbxMeta;
import de.soderer.utilities.kdbx.data.KdbxTimes;
import de.soderer.utilities.kdbx.data.KdbxUUID;
import de.soderer.utilities.kdbx.data.KeyDerivationFunctionInfo;
import de.soderer.utilities.kdbx.data.KeyDerivationFunctionInfoAes;
import de.soderer.utilities.kdbx.data.KeyDerivationFunctionInfoArgon;
import de.soderer.utilities.kdbx.utilities.CopyInputStream;
import de.soderer.utilities.kdbx.utilities.HmacInputStream;
import de.soderer.utilities.kdbx.utilities.HmacOutputStream;
import de.soderer.utilities.kdbx.utilities.Version;

/**
 * Checks the fluent setter convention of all classes with "withX(value)" methods:
 * each method returns the same object and the value can be read back by the matching getter ("getX()" or "isX()"), if there is one.
 */
@SuppressWarnings("static-method")
public class FluentSetterConventionTest {
	private static final ZonedDateTime SAMPLE_TIME = ZonedDateTime.of(2024, 5, 6, 7, 8, 9, 0, ZoneId.of("UTC"));

	/**
	 * Methods, whose value cannot be read back by a getter with the same value, or which need special input data
	 */
	private static final Set<String> EXCLUDED_METHODS = new LinkedHashSet<>(Arrays.asList(
			// Parses the given bytes as KDF parameters, tested separately
			"KdbxHeaderFormat4.withKdfParamsBytes",
			// Parse a VariantDictionary, tested separately
			"KeyDerivationFunctionInfoAes.withValues",
			"KeyDerivationFunctionInfoArgon.withValues"));

	/**
	 * Values for parameters with restricted ranges
	 */
	private static final Map<String, Object> SPECIAL_VALUES = new HashMap<>();
	static {
		SPECIAL_VALUES.put("KeyDerivationFunctionInfoArgon.withVersion", 0x10);
	}

	private static List<Supplier<Object>> createInstanceSuppliers() {
		final byte[] hmacKey = new byte[64];
		final List<Supplier<Object>> suppliers = new ArrayList<>();
		suppliers.add(KdbxDatabase::new);
		suppliers.add(() -> new KdbxReader(new ByteArrayInputStream(new byte[0])));
		suppliers.add(() -> new KdbxWriter(new ByteArrayOutputStream()));
		suppliers.add(KdbxBinary::new);
		suppliers.add(KdbxCustomDataItem::new);
		suppliers.add(KdbxEntry::new);
		suppliers.add(KdbxEntryBinary::new);
		suppliers.add(KdbxGroup::new);
		suppliers.add(KdbxHeaderFormat3::new);
		suppliers.add(KdbxHeaderFormat4::new);
		suppliers.add(KdbxMemoryProtection::new);
		suppliers.add(KdbxMeta::new);
		suppliers.add(KdbxTimes::new);
		suppliers.add(KeyDerivationFunctionInfoAes::new);
		suppliers.add(KeyDerivationFunctionInfoArgon::new);
		suppliers.add(() -> new CopyInputStream(new ByteArrayInputStream(new byte[0])));
		suppliers.add(() -> new HmacInputStream(new ByteArrayInputStream(new byte[0]), hmacKey));
		suppliers.add(() -> new HmacOutputStream(new ByteArrayOutputStream(), hmacKey));
		return suppliers;
	}

	/**
	 * Creates a sample value for a parameter type, which differs from the current value of the getter if possible
	 */
	private static Object createSampleValue(final Class<?> type, final Object currentValue) {
		if (type == String.class) {
			return "Sample value";
		} else if (type == int.class || type == Integer.class) {
			return 5;
		} else if (type == long.class || type == Long.class) {
			return 7L;
		} else if (type == boolean.class || type == Boolean.class) {
			return !Boolean.TRUE.equals(currentValue);
		} else if (type == byte[].class) {
			final byte[] value = new byte[32];
			Arrays.fill(value, (byte) 0x2A);
			return value;
		} else if (type == KdbxUUID.class) {
			return new KdbxUUID();
		} else if (type == ZonedDateTime.class) {
			return SAMPLE_TIME;
		} else if (type == KdbxTimes.class) {
			return new KdbxTimes().withUsageCount(3);
		} else if (type == KdbxMeta.class) {
			return new KdbxMeta().withDatabaseName("Sample");
		} else if (type == KdbxMemoryProtection.class) {
			return new KdbxMemoryProtection().withProtectNotes(true);
		} else if (type == KdbxHeaderFormat.class) {
			return new KdbxHeaderFormat3();
		} else if (type == KeyDerivationFunctionInfo.class) {
			return new KeyDerivationFunctionInfoAes();
		} else if (type == Version.class) {
			// Header formats only accept their own major version
			final Version version = (Version) currentValue;
			return new Version(version.getMajorVersionNumber(), version.getMinorVersionNumber() + 1, 0);
		} else if (type == ByteOrder.class) {
			return ByteOrder.BIG_ENDIAN;
		} else if (type == List.class) {
			return new ArrayList<>();
		} else if (type == Map.class) {
			return new LinkedHashMap<>();
		} else if (type == Set.class) {
			return new LinkedHashSet<>(Arrays.asList("Key"));
		} else if (type.isEnum()) {
			for (final Object enumConstant : type.getEnumConstants()) {
				if (enumConstant != currentValue) {
					return enumConstant;
				}
			}
			return type.getEnumConstants()[0];
		} else {
			throw new IllegalStateException("No sample value for type " + type.getName());
		}
	}

	private static Method findGetter(final Class<?> objectClass, final String propertyName) {
		for (final String prefix : new String[] { "get", "is" }) {
			try {
				final Method getter = objectClass.getMethod(prefix + propertyName);
				if (getter.getParameterCount() == 0) {
					return getter;
				}
			} catch (@SuppressWarnings("unused") final NoSuchMethodException e) {
				// try next prefix
			}
		}
		return null;
	}

	@Test
	public void testFluentSettersReturnThisAndSetValue() throws Exception {
		int checkedMethods = 0;
		for (final Supplier<Object> instanceSupplier : createInstanceSuppliers()) {
			final Class<?> objectClass = instanceSupplier.get().getClass();
			for (final Method method : objectClass.getMethods()) {
				final String methodId = objectClass.getSimpleName() + "." + method.getName();
				if (!method.getName().startsWith("with") || method.getParameterCount() != 1 || Modifier.isStatic(method.getModifiers()) || EXCLUDED_METHODS.contains(methodId)) {
					continue;
				}

				final Object instance = instanceSupplier.get();
				final String propertyName = method.getName().substring(4);
				final Method getter = findGetter(objectClass, propertyName);
				final Object currentValue = getter == null ? null : getter.invoke(instance);
				final Object value = SPECIAL_VALUES.containsKey(methodId) ? SPECIAL_VALUES.get(methodId) : createSampleValue(method.getParameterTypes()[0], currentValue);

				final Object result;
				try {
					result = method.invoke(instance, value);
				} catch (final InvocationTargetException e) {
					fail(methodId + " failed for value " + value + ": " + e.getCause(), e.getCause());
					return;
				}
				assertSame(instance, result, methodId + " must return this");

				if (getter != null) {
					final Object readValue = getter.invoke(instance);
					if (value instanceof byte[]) {
						assertArrayEquals((byte[]) value, (byte[]) readValue, methodId);
					} else {
						assertEquals(value, readValue, methodId);
					}
				}
				checkedMethods++;
			}
		}
		// Protects against a test, which silently checks nothing
		assertTrue(checkedMethods > 100, "Only " + checkedMethods + " methods checked");
	}

	@Test
	public void testEverySetterHasFluentVariant() {
		final List<String> missingFluentSetters = new ArrayList<>();
		for (final Supplier<Object> instanceSupplier : createInstanceSuppliers()) {
			final Class<?> objectClass = instanceSupplier.get().getClass();
			for (final Method method : objectClass.getDeclaredMethods()) {
				if (Modifier.isPublic(method.getModifiers()) && !Modifier.isStatic(method.getModifiers()) && method.getName().startsWith("set") && method.getName().length() > 3) {
					try {
						objectClass.getMethod("with" + method.getName().substring(3), method.getParameterTypes());
					} catch (@SuppressWarnings("unused") final NoSuchMethodException e) {
						missingFluentSetters.add(objectClass.getSimpleName() + "." + method.getName());
					}
				}
			}
		}
		// Known setters without fluent variant
		missingFluentSetters.removeAll(Arrays.asList("KeyDerivationFunctionInfoAes.setAesKdbxType"));
		assertEquals(new ArrayList<>(), missingFluentSetters);
	}
}
