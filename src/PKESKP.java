import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created with IntelliJ IDEA.
 * User: cat
 * Date: 15.10.12
 * Time: 21:06
 * To change this template use File | Settings | File Templates.
 */
public class PKESKP {
    // Public-Key Encrypted Session Key Packet
    // ------ header -----
    // C1 -- packet tag -- Public Key Encrypted Session Key Packet
    // 00 -- length
    byte pTag;
    byte length;
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
        pTag = (byte)0xC1;
        length = 0;
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
        res[1]  = res[2];
        System.arraycopy(res, 0, formatted_key, symmetric_key.length+ 1, 2);
        encrKey = new MPI(RSA.RSA_operation(Utilities.getHexString(formatted_key), pub_exp, mod));
        // 12 -- packet header, 2 + encrKey.len() -- MPI
        length = Utilities.toBytes(12 + 2 + encrKey.len())[3];
    }
    PKESKP(InputStream in) throws Exception
    {
        byte[] arr=new byte[1];
        in.read(arr);
        pTag=arr[0];
        in.read(arr);
        length=arr[0];
        in.read(arr);
        version=arr[0];
        keyID= new byte[8];
        in.read(keyID,0,8);
        in.read(arr);
        PKAID=arr[0];
        encrKey= new MPI(in);
    }
    public void dump(OutputStream out) throws Exception{
        out.write(pTag & 0xff);
        out.write(length & 0xff);
        out.write(version & 0xff);
        for(int i : keyID)
            out.write(i & 0xff);
        out.write(PKAID & 0xff);
        encrKey.dump(out);
    }
}