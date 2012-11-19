import java.util.Random;

/**
 * Date: 19.11.12
 * Time: 3:15
 */
public class PKCS1 {
    public static byte[] encrypt(byte[] message, int k) throws Exception {
        byte[] ps = new byte[k - message.length - 3];
        new Random().nextBytes(ps);
        for (int i = 0; i < ps.length; i++)
            if (ps[i] == 0x00) ps[i] = (byte) 0x01;
        byte[] encoded_message = new byte[message.length + ps.length + 3];
        encoded_message[0] = (byte) 0x00;
        encoded_message[1] = (byte) 0x02;
        for (int i = 0; i < ps.length; i++)
            encoded_message[i + 2] = ps[i];
        encoded_message[ps.length + 2] = (byte) 0x00;
        for (int i = 0; i < message.length; i++)
            encoded_message[i + ps.length + 3] = message[i];
        return encoded_message;
    }

    public static byte[] decrypt(byte[] encoded_message) throws Exception {
        if (encoded_message[0] == (byte) 0x02) {
            int padding;
            for (padding = 1; encoded_message[padding] != (byte) 0x00; padding++) ;
            byte[] decoded_message = new byte[encoded_message.length - 1 - padding];
            System.arraycopy(encoded_message, padding + 1, decoded_message, 0, decoded_message.length);
            return decoded_message;
        } else return new byte[0];
    }
}
