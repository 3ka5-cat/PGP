import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.Arrays;

public class SP implements Constants {
    // Signature Packet
    // ------ header -----
    // C2 -- packet tag -- Signature Packet
    byte packet_tag;
    byte packet_length;
    byte version;
    byte length;
    byte sign_type;
    byte[] time = new byte[4];
    byte[] key_id = new byte[8];
    byte PKA_id;
    byte HA_id;
    MPI signature;

    byte[] sign_header = new byte[5];

    SP(String file, String pub_exp, String priv_exp, String mod) throws Exception {
        packet_tag = (byte) SP_TAG;
        version = 3;
        length = 5; // always 5
        sign_type = (byte) TXTSIGN_TYPE; //Signature of a canonical text document
        //TODO: bigendian?
        time = Utilities.toBytes((int) (System.currentTimeMillis() / 1000L));
        //For a V3 key, the eight-octet Key ID consists of the low 64 bits of
        //the public modulus of the RSA key
        byte[] pub = Utilities.hex2Byte(pub_exp);
        Arrays.fill(key_id, (byte) 0);
        for (int i = 0; i < pub.length && i < key_id.length; ++i) {
            key_id[i] = pub[i];
        }
        PKA_id = RSA_ID;
        HA_id = SHA1_ID;
        //The concatenation of the data to be signed, the signature type, and
        //creation time from the Signature packet (5 additional octets) is
        //hashed.  The resulting hash value is used in the signature algorithm.
        //The high 16 bits (first two octets) of the hash are included in the
        //Signature packet to provide a quick test to reject some invalid
        //signatures.
        //
        //All signatures are formed by producing a hash over the signature
        //data, and then using the resulting hash in the signature algorithm.
        //
        //Once the data body is hashed, then a trailer is hashed.  A V3
        //signature hashes five octets of the packet body, starting from the
        //signature type field.  This data is the signature type, followed by
        //the four-octet signature time.
        sign_header[0] = sign_type;
        System.arraycopy(sign_header, 1, time, 0, 4);
        //signature = new MPI(RSA.RSA_operation(Utilities.getHexString(getHash(file)), priv_exp, mod));
        //EMSA_PKCS_Encoding(file,60);
        // 19 -- packet header, 2 + signature.len() -- MPI
        signature = new MPI(RSA.RSAoperation(Utilities.getHexString(EMSA_PKCS_Encoding(file, 50)), priv_exp, mod));
        //signature = new MPI(EMSA_PKCS_Encoding(file,50));
        packet_length = Utilities.toBytes(19 + 2 + 2 + signature.len())[3]; //3 for big endian
    }

    SP(RandomAccessFile in) throws Exception {
        if (((packet_tag = (byte) in.read()) & 0xff) == SP_TAG) {
            packet_length = (byte) in.read();
            version = (byte) in.read();
            length = (byte) in.read();
            sign_type = (byte) in.read();
            in.read(time, 0, 4);
            in.read(key_id, 0, 8);
            PKA_id = (byte) in.read();
            HA_id = (byte) in.read();
            in.read();
            in.read(); //2 sign bytes
            signature = new MPI(in);
            sign_header[0] = sign_type;
            System.arraycopy(sign_header, 1, time, 0, 4);
        } else
            System.out.println("Not SP packet");
    }

    public byte[] getHash(String file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        FileInputStream input_file = new FileInputStream(file);
        byte[] data_bytes = new byte[1024];
        for (int i = 0; i < data_bytes.length && i < sign_header.length; ++i)
            data_bytes[i] = sign_header[i];
        int read = 0;
        int offset = sign_header.length;
        while ((read = input_file.read(data_bytes, offset, data_bytes.length - offset)) != -1) {
            md.update(data_bytes, 0, read);
            offset = 0;
        }
        input_file.close();
        return md.digest();
    }

    public byte[] EMSA_PKCS_Encoding(String file, int emLen) throws Exception {
        byte[] SHA1_DER = new byte[]{(byte) 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
        byte[] Hash = getHash(file);
        byte[] T = new byte[Hash.length + SHA1_DER.length];
        System.arraycopy(SHA1_DER, 0, T, 0, SHA1_DER.length);
        System.arraycopy(Hash, 0, T, SHA1_DER.length, Hash.length);
        byte[] PS = new byte[emLen - T.length - 3];
        for (int i = 0; i < PS.length; i++)
            PS[i] = (byte) 0xff;
        byte[] encoded_message = new byte[3 + PS.length + T.length];
        encoded_message[0] = (byte) 0x00;
        encoded_message[1] = (byte) 0x01;
        for (int i = 0; i < PS.length; i++)
            encoded_message[i + 2] = PS[i];
        encoded_message[PS.length + 2] = 0x00;
        for (int i = 0; i < T.length; i++)
            encoded_message[i + PS.length + 3] = T[i];
        return encoded_message;

    }

    public void dump(FileOutputStream out) throws Exception {
        out.write(packet_tag & 0xff);
        out.write(packet_length & 0xff);
        out.write(version & 0xff);
        out.write(length & 0xff);
        out.write(sign_type & 0xff);
        for (int i : time)
            out.write(i & 0xff);
        for (int i : key_id)
            out.write(i & 0xff);
        out.write(PKA_id & 0xff);
        out.write(HA_id & 0xff);
        out.write(signature.MPI_string[0] & 0xff);
        out.write(signature.MPI_string[1] & 0xff);
        signature.dump(out);
    }
}
