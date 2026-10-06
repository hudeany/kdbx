package de.soderer.utilities.kdbx.utilities;

import java.nio.charset.StandardCharsets;

/**
 * Typed value of a {@link VariantDictionary}.
 */
public class VariantDictionaryEntry {
	/**
	 * Value types of the VariantDictionary format.
	 */
	public enum Type {
		/**
		 * End marker of the dictionary.
		 */
		END(0x00, Void.class),
		/**
		 * Unsigned 32 bit integer, represented as Java Integer.
		 */
		UINT_32(0x04, Integer.class), // unsigned
		/**
		 * Unsigned 64 bit integer, represented as Java Long.
		 */
		UINT_64(0x05, Long.class), // unsigned
		/**
		 * Boolean value.
		 */
		BOOL(0x08, Boolean.class),
		/**
		 * Signed 32 bit integer.
		 */
		INT_32(0x0C, Integer.class),
		/**
		 * Signed 64 bit integer.
		 */
		INT_64(0x0D, Long.class),
		/**
		 * UTF-8 text.
		 */
		STRING(0x18, String.class), // UTF-8 String
		/**
		 * Byte array.
		 */
		BYTE_ARRAY(0x42, byte[].class);

		/**
		 * Type id in the binary format.
		 */
		private final int id;
		/**
		 * Java type of the values.
		 */
		private final Class<?> javaType;

		/**
		 * Returns the type id in the binary format.
		 *
		 * @return the type id
		 */
		public int getId() {
			return id;
		}

		/**
		 * Returns the Java type of the values.
		 *
		 * @return the Java type
		 */
		public Class<?> getJavaType() {
			return javaType;
		}

		/**
		 * Creates the constant.
		 *
		 * @param id type id in the binary format
		 * @param javaType Java type of the values
		 */
		Type(final int id, final Class<?> javaType) {
			this.id = id;
			this.javaType = javaType;
		}

		/**
		 * Returns the type for a type id.
		 *
		 * @param typeId type id in the binary format
		 * @return the type
		 * @throws RuntimeException for unknown type ids
		 */
		public static Type fromTypeId(final int typeId) {
			for (final Type type : Type.values()) {
				if (type.id == typeId) {
					return type;
				}
			}
			throw new RuntimeException("Invalid type id: " + "0x" + Integer.toHexString(typeId));
		}

		/**
		 * Converts a Java value to the binary format of this type.
		 *
		 * @param value Java value matching this type
		 * @return the binary data
		 */
		public byte[] fromJavaValue(final Object value) {
			switch (this) {
				case END:
					return new byte[0];
				case STRING:
					return ((String) value).getBytes(StandardCharsets.UTF_8);
				case INT_32:
					return Utilities.getLittleEndianBytes((Integer) value);
				case INT_64:
					return Utilities.getLittleEndianBytes((Long) value);
				case UINT_32:
					return Utilities.getLittleEndianBytes((Integer) value); // unsigned
				case UINT_64:
					return Utilities.getLittleEndianBytes((Long) value); // unsigned
				case BOOL:
					return new byte[] { (byte) ((Boolean) value ? 1 : 0) };
				case BYTE_ARRAY:
					return (byte[]) value;
				default:
					throw new IllegalArgumentException("Unknown VariantDictionary type");
			}
		}

		/**
		 * Converts binary data of this type to a Java value.
		 *
		 * @param value the binary data
		 * @return the Java value
		 * @throws RuntimeException for data of invalid length
		 */
		public Object toJavaValue(final byte[] value) {
			switch (this) {
				case END:
					return null;
				case STRING:
					return new String(value, StandardCharsets.UTF_8);
				case INT_32:
					return Utilities.readIntFromLittleEndianBytes(value);
				case INT_64:
					return Utilities.readLongFromLittleEndianBytes(value);
				case UINT_32:
					return Utilities.readIntFromLittleEndianBytes(value);
				case UINT_64:
					return Utilities.readLongFromLittleEndianBytes(value);
				case BOOL:
					if (value.length != 1) {
						throw new IllegalArgumentException(this + " requires a 1-byte value, got " + value.length + " bytes");
					} else if (value[0] == 0) {
						return Boolean.FALSE;
					} else if (value[0] == 1) {
						return Boolean.TRUE;
					} else {
						throw new IllegalArgumentException(this + " requires a 1-byte value of either 0 or 1");
					}
				case BYTE_ARRAY:
					return value;
				default:
					throw new IllegalArgumentException("Unknown VariantDictionary");
			}
		}
	}

	/**
	 * Type of the value.
	 */
	private final Type type;
	/**
	 * Binary data of the value.
	 */
	private byte[] value;

	/**
	 * Returns the type of the value.
	 *
	 * @return the type
	 */
	public Type getType() {
		return type;
	}

	/**
	 * Returns the binary data of the value.
	 *
	 * @return the binary data
	 */
	public byte[] getValue() {
		return value;
	}

	/**
	 * Creates an entry.
	 *
	 * @param type type of the value
	 * @param value binary data of the value
	 */
	public VariantDictionaryEntry(final Type type, final byte[] value) {
		this.type = type;
		this.value = value;
	}

	/**
	 * Returns the value as Java object.
	 *
	 * @return the Java value
	 */
	public Object getJavaValue() {
		return type.toJavaValue(value);
	}

	/**
	 * Sets the value from a Java object.
	 *
	 * @param value Java value matching the type
	 */
	public void setJavaValue(final Object value) {
		this.value = type.fromJavaValue(value);
	}
}
