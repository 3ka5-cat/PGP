import java.math.BigInteger;

/**
 * Created with IntelliJ IDEA.
 * User: cat
 * Date: 15.10.12
 * Time: 21:09
 * To change this template use File | Settings | File Templates.
 */
public class Utilities {
    public static String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    public static byte[] toBytes(BigInteger bigInteger) {
        byte[] array = bigInteger.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return array;
    }

    public static byte[] toBytes(int i) {
        byte[] result = new byte[4];
        result[0] = (byte) (i >> 24);
        result[1] = (byte) (i >> 16);
        result[2] = (byte) (i >> 8);
        result[3] = (byte) (i /*>> 0*/);
        return result;
    }

    public static int toInt(byte[] byte_array)
    {
        return ((byte_array[0] & 0xFF) << 24) +
                ((byte_array[1] & 0xFF) << 16) +
                ((byte_array[2] & 0xFF) << 8) +
                (byte_array[3] & 0xFF);
    }
}
