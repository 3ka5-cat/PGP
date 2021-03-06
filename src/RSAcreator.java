import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;

//import javax.crypto.SecretKeyFactory;
//import javax.crypto.spec.DESedeKeySpec;

public class RSAcreator implements Constants {
    SecretKey key;
    String pub_exp;
    String mod;
    String priv_exp;

    RSAcreator() throws Exception {   //DESede -- Triple DES Encryption
        key = KeyGenerator.getInstance("DESede").generateKey();
        /*
        byte[] keyBytes = "0123456789ABCDEFABCDEF01234567890123456789ABCDEF".getBytes("ASCII");
        DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
        key = factory.generateSecret(keySpec);
        */
        //String format = key.getFormat();
        //System.out.println(format);
        pub_exp = "10001";
        mod = "966CC1A67319C5EB3166BB0FFAD73D81CF501D9BE254CB6B1346092D0499E816517FF8D55839292774C5890A4AFA30406B87DEFB96C1F5BC2A10B5C2E0755E6B266EFED871F15F0E34446EA5A0F369542A44FF2BBAF06F7E5C38C12DA0A9FF4D95A5DD06EAAD15F5BCED0ED96F560E5119552C5AC1117A77715F56997ECA1AC7";
        priv_exp = "391A9A3D04EEE0CA931B6BA1FA58A179D8E89204EE5BC0492AACE8A8D55953D8BD21B6A5CEF30C237559D3D73B7554C1EFD0499EFAB131073874D57B60584DFA0B16FC05AF2EF13E24DDF49982B6E59E7C6643AF2B9FF9837A85DA9C814662F35BC45DFA6CA01E5F10DBACA762AB31861E615B2D14E7179EBA6FA37575BBEA29";
    }

    public void sign(String file, String encrypted_file) throws Exception {
        FileOutputStream PGP_file = new FileOutputStream(encrypted_file, true);
        SP sp = new SP(file, pub_exp, priv_exp, mod);
        sp.dump(PGP_file);
        //PGP_file.write((byte)0xDE);
        //PGP_file.write((byte)0xAD);
        PGP_file.close();
    }

    public void checkSign(String file, String encrypted_file) throws Exception {
        RandomAccessFile PGP_file = new RandomAccessFile(encrypted_file, "r");
        int len = -1;
        byte[] arr = new byte[2];

        while ((len = PGP_file.read(arr)) != -1 && (arr[0] & 0xff) != SP_TAG) {
            //System.out.println("checkSign: skip packet for SP");
            PGP_file.seek(arr[1] & 0xff);
        }

        if (len > 0) {
            PGP_file.seek(PGP_file.getFilePointer() - 2);
            SP sp = new SP(PGP_file);
            //byte[] sign = sp.signature.MPI_string;
            byte[] sign = (RSA.RSAoperation(Utilities.getHexString(sp.signature.MPI_string),
                    pub_exp, mod));
            if (sign[0] == (byte) 0x01) {
                int padding = 1;
                for (; sign[padding] != (byte) 0x00; padding++) ;
                byte[] hash = new byte[sign.length - padding - 16];
                System.arraycopy(sign, padding + 16, hash, 0, hash.length);
                System.out.println("Decrypted Hash:: " + Utilities.getHexString(hash));
                System.out.println("Hash of decrypted file:: " + Utilities.getHexString(sp.getHash(file)));
            } else
                System.out.println("Wrong padding");
        } else
            System.out.println("checkSign: can't find SP packet");
        PGP_file.close();
    }

    public void encrypt(String file, String encrypted_file) throws Exception {
        FileInputStream input_file = new FileInputStream(file);
        FileOutputStream PGP_file = new FileOutputStream(encrypted_file, true);
        PKESKP keyPacket = new PKESKP(key, pub_exp, mod);
        keyPacket.dump(PGP_file);
        Des encryptor = new Des(key);
        encryptor.encrypt(input_file, PGP_file);
        input_file.close();
        PGP_file.close();
    }

    public void decrypt(String file, String encrypted_file) throws Exception {
        RandomAccessFile PGP_file = new RandomAccessFile(encrypted_file, "r");
        int len = -1;
        byte[] arr = new byte[2];
        while ((len = PGP_file.read(arr)) != -1 && (arr[0] & 0xff) != PKESKP_TAG) {
            //System.out.println("decrypt: skip packet for PKESKP");
            PGP_file.seek(arr[1] & 0xff);
        }
        if (len > 0) {
            PGP_file.seek(PGP_file.getFilePointer() - 2);
            FileOutputStream output_file = new FileOutputStream(file);
            PKESKP key_packet = new PKESKP(PGP_file);
            byte[] formatted_decr_key =
                    RSA.RSAoperation(Utilities.getHexString(key_packet.encr_key.MPI_string), priv_exp, mod);
            formatted_decr_key = PKCS1.decrypt(formatted_decr_key);
            byte[] real_key = new byte[formatted_decr_key.length - 3];
            System.arraycopy(formatted_decr_key, 1, real_key, 0, real_key.length);
            //BigInteger test = new BigInteger(real_key);
            //String hexKey = test.toString(16);
            //int hc = hexKey.hashCode();
            if (formatted_decr_key[0] == TRIPLEDES_ID) {
                SecretKeySpec ks = new SecretKeySpec(real_key, "DESede");
                Des decryptor = new Des(ks);
                decryptor.decrypt(PGP_file, output_file);
            } else
                System.out.println("Decrypt RSA PKESKP: id of symmetric encryption algorithm used to encrypt " +
                        "data isn't TripleDES");
            output_file.close();
        } else
            System.out.println("Decrypt: can't find PKESKP packet");
        PGP_file.close();
    }
}


