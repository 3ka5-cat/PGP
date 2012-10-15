/**
 * Created with IntelliJ IDEA.
 * User: cat
 * Date: 15.10.12
 * Time: 21:08
 * To change this template use File | Settings | File Templates.
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class Des {
    // because of strange 2-octet length field in the header
    // TODO: how to write 1024 as length to 2-octet length field in the header
    Cipher ecipher;
    Cipher dcipher;
    Des(SecretKey key) throws Exception{
        byte[] iv = new byte[] { (byte) 0x8E, 0x12, 0x39, (byte) 0x9C, 0x07, 0x72, 0x6F, 0x5A };
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        // CBC: Cipher Block Chaining Mode
        // PKCS5Padding: The padding scheme
        //ecipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        ecipher = Cipher.getInstance("DESede/ECB/NoPadding");
        dcipher = Cipher.getInstance("DESede/ECB/NoPadding");

        ecipher.init(Cipher.ENCRYPT_MODE, key);//, paramSpec);
        dcipher.init(Cipher.DECRYPT_MODE, key);//, paramSpec);
    }

    public void encrypt(InputStream in, OutputStream out)  throws Exception{
        //out = new CipherOutputStream(out, ecipher);
        byte[] header = new byte[2];
        // Symmetrically Encrypted Data Packet
        // ------ header -----
        // C3 -- packet tag -- Public Key Encrypted Session Key Packet
        // 191 -- length -- max 1-octet length
        header[0] = (byte)0xC3;
        int len = 0;

        byte[] buf = new byte[200];
        while ((len = in.read(buf)) >= 0) {
            //Write Symmetrically Encrypted Data Packet
            System.out.println(new String(buf));
            out.write(header[0] & 0xff);
            len = ecipher.getOutputSize(len);
            byte[] cipherText = new byte[len];
            len = ecipher.update(buf, 0, len, cipherText);
            header[1] = (byte)len;
            out.write(header[1] & 0xff);
            out.write(cipherText, 0, len);
            String hex = new String(cipherText);
            int hc = hex.hashCode();
            byte a = 0;
            Arrays.fill(buf, a);
            //encrypt_block(in,out,len);
        }
        /*
        byte[] cipherText = new byte[ecipher.getOutputSize(len)];
        len = ecipher.doFinal(buf, 0, 0, cipherText, 0);
        if (len != 0) {
            out.write(cipherText, 0, len);
        }
        */
        out.flush();
        out.close();
    }
    /*
    void encrypt_block(InputStream in,OutputStream out,int numRead) throws Exception
    {
        OutputStream hm=new CipherOutputStream(out,ecipher);
        hm.write(buf,0,numRead);
    }
    */
    public void decrypt(InputStream in, OutputStream out)  throws Exception{
        //in = new CipherInputStream(in, dcipher);
        int read = 0;
        byte[] header= new byte[2];

        while (in.read(header,0,2) >= 0) {
            byte[] buf = new byte[header[1] & 0xff];
            read = in.read(buf,0,header[1] & 0xff);
            String hex = new String(buf);
            int hc = hex.hashCode();
            byte[] decrypted = new byte[header[1] & 0xff];
            //decrypt_block(in,out,read);
            dcipher.update(buf,0,read,decrypted);
            System.out.println(new String(decrypted));
            //decrypt_block(in,out,t);
        }
        out.close();
    }
    /*
    void decrypt_block(InputStream in,OutputStream out,int len) throws Exception{
        InputStream hm = new CipherInputStream(in,dcipher);
        byte[] buf = new byte[191];
        int numRead=in.read(buf,0,len);
        //out.write(buf,0,numRead);
        System.out.println(new String(buf));
        hm.close();
    }
    */
}