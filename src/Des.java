import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;

//import javax.crypto.spec.IvParameterSpec;
//import java.security.spec.AlgorithmParameterSpec;

public class Des implements Constants {
    // because of strange 2-octet packet_length field in the header
    // TODO: how to write 1024 as packet_length to 2-octet packet_length field in the header
    Cipher ecipher;
    Cipher dcipher;
    byte version;

    Des(SecretKey key) throws Exception {
        //byte[] iv = new byte[] { (byte) 0x8E, 0x12, 0x39, (byte) 0x9C, 0x07, 0x72, 0x6F, 0x5A };
        //AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        //ecipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        ecipher = Cipher.getInstance("DESede/ECB/NoPadding");
        dcipher = Cipher.getInstance("DESede/ECB/NoPadding");

        ecipher.init(Cipher.ENCRYPT_MODE, key);//, paramSpec);
        dcipher.init(Cipher.DECRYPT_MODE, key);//, paramSpec);
    }

    public void encrypt(InputStream in, OutputStream out) throws Exception {
        // Symmetrically Encrypted Data Packet
        version = 4;
        int block_size = ecipher.getBlockSize();
        int len = 0;
        byte[] buf = new byte[184];
        int add = 0;
        int packet_len;
        byte[] padded_buf;
        System.out.println("Encrypted file:: ");
        while ((len = in.read(buf)) >= 0) {
            System.out.println(new String(buf));
            out.write((byte) SEDP_TAG & 0xff);
            // pad with 0 for
            if ((len % block_size) != 0) {
                add = block_size - (len - block_size * (len / block_size));
                padded_buf = new byte[len + add];
                Arrays.fill(padded_buf, (byte) 0);
                for (int i = 0; i < len + add; ++i)
                    padded_buf[i] = buf[i];
            }
            packet_len = len + add + 1 + 1 + 1;  // data + padding + version + sym_alg_id + S2K
            out.write((byte) packet_len & 0xff);
            out.write(version & 0xff);
            out.write(TRIPLEDES_ID & 0xff);
            out.write(S2K_reserved & 0xff);
            byte[] cipher_text = new byte[len + add];
            len = ecipher.update(buf, 0, len + add, cipher_text);
            out.write(cipher_text, 0, len);
            Arrays.fill(buf, (byte) 0);
        }
        out.flush();
    }

    public void decrypt(RandomAccessFile in, OutputStream out) throws Exception {
        int block_size = dcipher.getBlockSize();
        int read = 0;
        byte[] header = new byte[2];
        int len = 0;
        System.out.println("Decrypted file:: ");
        while (in.read(header, 0, 2) != -1 && ((header[0] & 0xff) == SEDP_TAG)) {
            len = header[1] & 0xff;
            version = (byte) in.read();
            in.read();  // sym_alg
            in.read();  // s2k
            len -= 3;
            if ((len % block_size) != 0)
                len += block_size - (len - block_size * (len / block_size));
            byte[] buf = new byte[len];
            read = in.read(buf, 0, len);
            byte[] decrypted = new byte[len];
            dcipher.update(buf, 0, read, decrypted);
            int j;
            for (j = decrypted.length; decrypted[j - 1] == (byte) 0x00; j--)
                len--;
            out.write(decrypted, 0, len & 0xff);
            System.out.println(new String(decrypted));
        }
    }

}