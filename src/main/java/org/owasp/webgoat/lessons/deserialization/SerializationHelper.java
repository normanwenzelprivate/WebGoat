package org.owasp.webgoat.lessons.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.InvalidClassException;
import java.io.ObjectStreamClass;
import java.util.Base64;

public class SerializationHelper {

    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    /**
     * Custom ObjectInputStream that only allows deserialization of classes from a safe whitelist.
     */
    private static class SafeObjectInputStream extends ObjectInputStream {
        private static final String[] ALLOWED_CLASSES = {
            "java.lang.String",
            "java.util.ArrayList",
            "java.util.HashMap",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Boolean",
            "java.lang.Double",
            "java.lang.Float",
            "java.lang.Byte",
            "java.lang.Short",
            "java.util.LinkedList",
            "java.util.Date"
        };

        public SafeObjectInputStream(ByteArrayInputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();
            for (String allowed : ALLOWED_CLASSES) {
                if (allowed.equals(className)) {
                    return super.resolveClass(desc);
                }
            }
            throw new InvalidClassException("Unauthorized deserialization attempt: " + className);
        }
    }

    public static Object fromString(String s) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        try (SafeObjectInputStream ois = new SafeObjectInputStream(new ByteArrayInputStream(data))) {
            Object o = ois.readObject();
            return o;
        }
    }

    public static String toString(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    public static String show() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeLong(-8699352886133051976L);
        dos.close();
        byte[] longBytes = baos.toByteArray();
        return bytesToHex(longBytes);
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
