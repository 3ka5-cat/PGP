import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;

public class PKESKP {
    final static int PKESKPTAG = 0xC1;
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
        encrKey = new MPI(RSA.RSA_operation(Utilities.getHexString(formatted_key), pub_exp, mod));
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