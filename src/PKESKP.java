import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;

public class PKESKP implements Constants {
    // Public-Key Encrypted Session Key Packet
    // ------ header -----
    // C1 -- packet tag -- Public Key Encrypted Session Key Packet
    byte packet_tag;
    byte packet_length;
    // ------ data ------
    // 03 -- Version
    //TODO: wrong, it must be 64 bits of public key, look at rfc
    // 0000 0000 0000 0002 -- Key ID -- Triple DES
    // 01 -- Public-Key Algorithm ID -- RSA (Encrypt or Sign)
    // ------ MPI of RSA encrypted key ------
    // 00 00 -- Length of the MPI in bits
    // strings of octets -- encrypted key
    byte version;
    byte[] key_id;
    byte PKA_id;
    MPI encr_key;

    PKESKP(SecretKey key, String pub_exp, String mod) throws Exception {
        packet_tag = (byte) PKESKP_TAG;
        version = 3;
        key_id = new byte[]{0, 0, 0, 0, 0, 0, 0, 2};
        PKA_id = 1;

        byte[] symmetric_key = key.getEncoded();
        //String key_string = getHexString(symmetric_key);
        //int hc = key_string.hashCode();
        byte[] formatted_key = new byte[symmetric_key.length + 3];
        System.arraycopy(symmetric_key, 0, formatted_key, 1, symmetric_key.length);
        formatted_key[0] = TRIPLEDES_ID;
        int sum = 0;
        for (int i = 0; i < symmetric_key.length; ++i)
            sum += symmetric_key[i] % 65536;
        byte[] res = Utilities.toBytes(sum);
        res[0] = res[3];
        res[1] = res[2];
        System.arraycopy(res, 0, formatted_key, symmetric_key.length + 1, 2);
        //encr_key = new MPI(RSA.RSA_operation(Utilities.getHexString(formatted_key), pub_exp, mod));
        encr_key = new MPI(RSA.RSAoperation(Utilities.getHexString(PKCS1.encrypt(formatted_key, 50)), pub_exp, mod));
        // 12 -- packet header, 2 + encr_key.len() -- MPI
        packet_length = Utilities.toBytes(12 + 2 + encr_key.len())[3]; //3 for big endian
    }

    PKESKP(RandomAccessFile in) throws Exception {
        if (((packet_tag = (byte) in.read()) & 0xff) == PKESKP_TAG) {
            packet_length = (byte) in.read();
            version = (byte) in.read();
            key_id = new byte[8];
            in.read(key_id);
            PKA_id = (byte) in.read();
            encr_key = new MPI(in);
        } else
            throw new Exception("Not PKESKP packet");
    }


    public void dump(FileOutputStream out) throws Exception {
        out.write(packet_tag & 0xff);
        out.write(packet_length & 0xff);
        out.write(version & 0xff);
        for (int i : key_id)
            out.write(i & 0xff);
        out.write(PKA_id & 0xff);
        encr_key.dump(out);
    }
}