import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.util.Random;

public class PKESKP implements Constants{
    // Public-Key Encrypted Session Key Packet
    // ------ header -----
    // C1 -- packet tag -- Public Key Encrypted Session Key Packet
    byte pTag;
    byte pLength;
    // ------ data ------
    // 03 -- Version
    // 0000 0000 0000 0002 -- Key ID -- Triple DES
    // 01 -- Public-Key Algorithm ID -- RSA (Encrypt or Sign)
    // ------ MPI of RSA encrypted key ------
    // 00 00 -- Length of the MPI in bits
    // strings of octets -- encrypted key
    byte version;
    byte[] keyID;
    byte PKAID;
    MPI encrKey;

    PKESKP(SecretKey key, String pub_exp, String mod) throws Exception
    {
        pTag = (byte)PKESKPTAG;
        version = 3;
        keyID = new byte[]{0,0,0,0,0,0,0,2};
        PKAID = 1;

        byte[] symmetric_key = key.getEncoded();
        //String key_string = getHexString(symmetric_key);
        //int hc = key_string.hashCode();
        byte[] formatted_key = new byte[symmetric_key.length + 3];
        System.arraycopy(symmetric_key, 0, formatted_key, 1, symmetric_key.length);
        formatted_key[0] = 1;
        int sum = 0;
        for (int i = 0; i < symmetric_key.length; ++i)
            sum += symmetric_key[i] % 65536;
        byte[] res = Utilities.toBytes(sum);
        res[0] = res[3];
        res[1] = res[2];
        System.arraycopy(res, 0, formatted_key, symmetric_key.length+ 1, 2);
        //encrKey = new MPI(RSA.RSA_operation(Utilities.getHexString(formatted_key), pub_exp, mod));
        encrKey = new MPI(RSA.RSA_operation(Utilities.getHexString(pkcs1_encrypt(formatted_key,50)), pub_exp, mod));
        // 12 -- packet header, 2 + encrKey.len() -- MPI
        pLength = Utilities.toBytes(12 + 2 + encrKey.len())[3]; //3 for big endian
    }
    PKESKP(RandomAccessFile in) throws Exception
    {
        if (((pTag = (byte)in.read()) & 0xff) == PKESKPTAG) {
            pLength = (byte)in.read();
            version = (byte)in.read();
            keyID = new byte[8];
            in.read(keyID);
            PKAID = (byte)in.read();
            encrKey = new MPI(in);
        }
        else
            throw new Exception("Not PKESKP packet");
    }

    public byte[] pkcs1_encrypt(byte[] message, int k) throws Exception
    {
        byte[] ps = new byte[k - message.length - 3];
        new Random().nextBytes(ps);
        for(int i = 0; i < ps.length; i++)
            if(ps[i] == 0x00) ps[i] = (byte) 0x01;
        byte[] encoded_message = new byte[message.length + ps.length + 3];
        encoded_message[0] = (byte)0x00;
        encoded_message[1] = (byte)0x02;
        for(int i = 0; i < ps.length; i++)
            encoded_message[i+2] = ps[i];
        encoded_message[ps.length + 2] = (byte)0x00;
        for(int i = 0; i<message.length; i++)
            encoded_message[i + ps.length + 3] = message[i];
        return encoded_message;
    }

    public byte[] pkcs1_decrypt(byte[] encoded_message) throws  Exception
    {
        if(encoded_message[0] == (byte)0x02)
        {
            int padding;
            for(padding = 1; encoded_message[padding] != (byte)0x00; padding++)
                continue;
            byte[] decoded_message = new byte[encoded_message.length - 1 - padding];
            System.arraycopy(encoded_message,padding+1,decoded_message,0,decoded_message.length);
            return decoded_message;
        }
        else return new byte[0];
    }

    public void dump(FileOutputStream out) throws Exception{
        out.write(pTag & 0xff);
        out.write(pLength & 0xff);
        out.write(version & 0xff);
        for(int i : keyID)
            out.write(i & 0xff);
        out.write(PKAID & 0xff);
        encrKey.dump(out);
    }
}