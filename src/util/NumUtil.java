package util;
import java.lang.Math;
import java.nio.ByteBuffer;
import java.util.*;

public class NumUtil {


    public static int getBits(int b, int start, int end) {
        int len = end - start;
        b = b >> start;
        b = b & ((int) Math.pow(2, len) - 1);
        return b;
    }

    public static boolean isNordicAddress(long val) {
        return val >= 0x20000000;
    }

    public static boolean isInt(long val) {
        return val <= 65535;
    }

    public static String intToHexString(int val) {
        return String.format("0x%02X", val);
    }

    public static String intToHexStringWithout0x(int val) {
        return String.format("%02X", val);
    }

    public static String longToHexString(long val) {return String.format("%08X", val); }

    public static String byteToHexString(int val) {return String.format("%02X", val); }

    public static long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip
        return buffer.getLong();
    }

    public static HashMap sortByValues(HashMap map, boolean descendant) {
        List list = new LinkedList(map.entrySet());
        // Defined Custom Comparator here
        if (descendant) {
            Collections.sort(list, new Comparator() {
                public int compare(Object o1, Object o2) {
                    return ((Comparable) ((Map.Entry) (o2)).getValue())
                            .compareTo(((Map.Entry) (o1)).getValue());
                }
            });
        }
        else {
            Collections.sort(list, new Comparator() {
                public int compare(Object o1, Object o2) {
                    return ((Comparable) ((Map.Entry) (o1)).getValue())
                            .compareTo(((Map.Entry) (o2)).getValue());
                }
            });
        }

        // Here I am copying the sorted list in HashMap
        // using LinkedHashMap to preserve the insertion order
        HashMap sortedHashMap = new LinkedHashMap();
        for (Iterator it = list.iterator(); it.hasNext();) {
            Map.Entry entry = (Map.Entry) it.next();
            sortedHashMap.put(entry.getKey(), entry.getValue());
        }
        return sortedHashMap;
    }

    public static int[] LongToByteLittleEndian(long data) {
        int[] b = new int[4];
        for (int i=0; i<4; ++i) {
            b[i] = (int) data & 0xFF;
            data = data >> 8;
        }

        return b;
    }

    public static long byteToLongLittleEndian(long[] data) {
        if (data.length == 4)
            return data[0] + (data[1] << 8) + (data[2] << 16) + (data[3] << 24);
        else
            return 0; // should not happen here
    }

    /**
     * Round up the last i digits of a hex number
     */
    public static long hexRoundUp(long val, int i) {
        long roundUp = (long) Math.pow(16, i);
        long remainder = val % roundUp;
        if (remainder > roundUp/2)
            val = val + (roundUp - remainder);
        else
            val = val - remainder;

        return val;
    }

    public static void main(String[] args) {
        System.out.println(hexRoundUp(0x28e41, 3));
    }
}
