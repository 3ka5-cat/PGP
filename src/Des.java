import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;

//import javax.crypto.spec.IvParameterSpec;
//import java.security.spec.AlgorithmParameterSpec;

import java.util.Arrays;

public class Des implements Constants {
    // because of strange 2-octet pLength field in the header
    // TODO: how to write 1024 as pLength to 2-octet pLength field in the header
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
        int blockSize = ecipher.getBlockSize();
        int len = 0;
        byte[] buf = new byte[184];
        int add = 0;
        int packetLen;
        byte[] paddedBuf;
        System.out.println("Encrypted file:: ");
        while ((len = in.read(buf)) >= 0) {
            System.out.println(new String(buf));
            out.write((byte) SEDPTAG & 0xff);
            // pad with 0 for
            if ((len % blockSize) != 0) {
                add = blockSize - (len - blockSize * (len / blockSize));
                paddedBuf = new byte[len + add];
                Arrays.fill(paddedBuf, (byte) 0);
                for (int i = 0; i < len + add; ++i)
                    paddedBuf[i] = buf[i];
            }
            packetLen = len + add + 1;  // data + padding + version
            out.write((byte) packetLen & 0xff);
            out.write(version & 0xff);
            byte[] cipherText = new byte[len + add];
            len = ecipher.update(buf, 0, len + add, cipherText);
            out.write(cipherText, 0, len);
            Arrays.fill(buf, (byte) 0);
        }
        out.flush();
    }

    public void decrypt(RandomAccessFile in, OutputStream out) throws Exception {
        int blockSize = dcipher.getBlockSize();
        int read = 0;
        byte[] header = new byte[2];
        int len = 0;
        System.out.println("Decrypted file:: ");
        while (in.read(header, 0, 2) != -1 && ((header[0] & 0xff) == SEDPTAG)) {
            len = header[1] & 0xff;
            version = (byte) in.read();
            len--;
            if ((len % blockSize) != 0)
                len += blockSize - (len - blockSize * (len / blockSize));
            byte[] buf = new byte[len];
            read = in.read(buf, 0, len);
            byte[] decrypted = new byte[len];
            dcipher.update(buf, 0, read, decrypted);
            out.write(decrypted, 0, len & 0xff);
            System.out.println(new String(decrypted));
        }
    }

}