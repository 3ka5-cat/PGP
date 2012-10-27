import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.Arrays;

public class SP {
    final static int SPTAG = 0xC2;
    // Signature Packet
    // ------ header -----
    // C2 -- packet tag -- Signature Packet
    byte pTag;
    byte pLength;
    byte version;
    byte length;
    byte signType;
    //byte[] time = new byte[32];
    //byte[] keyID = new byte[64];
    byte PKAID;
    byte HAID;
    MPI signature;
    SP(String file, String pub_exp, String priv_exp, String mod) throws Exception
    {
        pTag = (byte)SPTAG;
        version = 3;
        length = 5;
        signType = (byte)0x01;
        //TODO: bigendian?
        //time = Utilities.toBytes((int)(System.currentTimeMillis() / 1000L));
        //For a V3 key, the eight-octet Key ID consists of the low 64 bits of
        //the public modulus of the RSA key
        //byte[] pub = Utilities.hex2Byte(pub_exp);
        //Arrays.fill(keyID, (byte) 0);
        //System.arraycopy(pub,0,keyID,0,keyID.pLength);
        PKAID = 1;
        HAID = 2;
        //Two-octet field holding left 16 bits of signed hash value.
        //what is it??
        signature = new MPI(RSA.RSA_operation(Utilities.getHexString(getHash(file)), priv_exp, mod));
        // 7 -- packet header, 2 + signature.len() -- MPI
        pLength = Utilities.toBytes(7 + 2 + signature.len())[3]; //3 for big endian
    }

    SP(RandomAccessFile in, String pub_exp, String mod) throws Exception
    {
        if (((pTag = (byte)in.read()) & 0xff) == SPTAG) {
            pLength = (byte)in.read();
            version = (byte)in.read();
            length = (byte)in.read();
            signType = (byte)in.read();
            //in.read(time,0,32);
            //in.read(keyID,0,64);
            PKAID = (byte)in.read();
            HAID = (byte)in.read();
            signature = new MPI(in);
        }
        else
            System.out.println("Not SP packet");
    }

    public static byte[] getHash(String file) throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        FileInputStream input_file = new FileInputStream(file);
        byte[] dataBytes = new byte[1024];
        int read = 0;
        while ((read = input_file.read(dataBytes)) != -1) {
            md.update(dataBytes, 0, read);
        }
        input_file.close();
        return md.digest();
    }

    public void dump(FileOutputStream out) throws Exception
    {
        out.write(pTag & 0xff);
        out.write(pLength & 0xff);
        out.write(version & 0xff);
        out.write(length & 0xff);
        out.write(signType & 0xff);
        //for(int i : time)
        //    out.write(i & 0xff);
        //for(int i : keyID)
        //    out.write(i & 0xff);
        out.write(PKAID & 0xff);
        out.write(HAID & 0xff);
        signature.dump(out);
    }
}
