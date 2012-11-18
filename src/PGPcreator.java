import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
//import javax.crypto.SecretKeyFactory;
//import javax.crypto.spec.DESedeKeySpec;
import java.io.RandomAccessFile;

public class PGPcreator implements Constants {
    SecretKey key;
    String pubExp;
    String mod;
    String privExp;

    PGPcreator() throws Exception {   //DESede -- Triple DES Encryption
        key = KeyGenerator.getInstance("DESede").generateKey();
        /*
        byte[] keyBytes = "0123456789ABCDEFABCDEF01234567890123456789ABCDEF".getBytes("ASCII");
        DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
        key = factory.generateSecret(keySpec);
        */
        //String format = key.getFormat();
        //System.out.println(format);
        pubExp = "10001";
        mod = "966CC1A67319C5EB3166BB0FFAD73D81CF501D9BE254CB6B1346092D0499E816517FF8D55839292774C5890A4AFA30406B87DEFB96C1F5BC2A10B5C2E0755E6B266EFED871F15F0E34446EA5A0F369542A44FF2BBAF06F7E5C38C12DA0A9FF4D95A5DD06EAAD15F5BCED0ED96F560E5119552C5AC1117A77715F56997ECA1AC7";
        privExp = "391A9A3D04EEE0CA931B6BA1FA58A179D8E89204EE5BC0492AACE8A8D55953D8BD21B6A5CEF30C237559D3D73B7554C1EFD0499EFAB131073874D57B60584DFA0B16FC05AF2EF13E24DDF49982B6E59E7C6643AF2B9FF9837A85DA9C814662F35BC45DFA6CA01E5F10DBACA762AB31861E615B2D14E7179EBA6FA37575BBEA29";
    }

    public void sign(String file, String encryptedFile) throws Exception {
        FileOutputStream PGPFile = new FileOutputStream(encryptedFile, true);
        SP sp = new SP(file, pubExp, privExp, mod);
        sp.dump(PGPFile);
        //PGPFile.write((byte)0xDE);
        //PGPFile.write((byte)0xAD);
        PGPFile.close();
    }

    public void checkSign(String file, String encryptedFile) throws Exception {
        RandomAccessFile PGPFile = new RandomAccessFile(encryptedFile, "r");
        int len = -1;
        byte[] arr = new byte[2];

        while ((len = PGPFile.read(arr)) != -1 && (arr[0] & 0xff) != SPTAG) {
            //System.out.println("checkSign: skip packet for SP");
            PGPFile.seek(arr[1] & 0xff);
        }

        if (len > 0) {
            PGPFile.seek(PGPFile.getFilePointer() - 2);
            SP sp = new SP(PGPFile);
            //byte[] sign = sp.signature.MPIstring;
            byte[] sign = (RSA.RSAOperation(Utilities.getHexString(sp.signature.MPIstring),
                    pubExp, mod));
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
        PGPFile.close();
    }

    public void encrypt(String file, String encryptedFile) throws Exception {
        FileInputStream inputFile = new FileInputStream(file);
        FileOutputStream PGPFile = new FileOutputStream(encryptedFile, true);
        PKESKP keyPacket = new PKESKP(key, pubExp, mod);
        keyPacket.dump(PGPFile);
        Des encryptor = new Des(key);
        encryptor.encrypt(inputFile, PGPFile);
        inputFile.close();
        PGPFile.close();
    }

    public void decrypt(String file, String encryptedFile) throws Exception {
        RandomAccessFile PGPFile = new RandomAccessFile(encryptedFile, "r");
        int len = -1;
        byte[] arr = new byte[2];
        while ((len = PGPFile.read(arr)) != -1 && (arr[0] & 0xff) != PKESKPTAG) {
            //System.out.println("decrypt: skip packet for PKESKP");
            PGPFile.seek(arr[1] & 0xff);
        }
        if (len > 0) {
            PGPFile.seek(PGPFile.getFilePointer() - 2);
            FileOutputStream outputFile = new FileOutputStream(file);
            PKESKP keyPacket = new PKESKP(PGPFile);
            byte[] formattedDecrKey =
                    RSA.RSAOperation(Utilities.getHexString(keyPacket.encrKey.MPIstring), privExp, mod);
            formattedDecrKey = keyPacket.pkcs1Decrypt(formattedDecrKey);
            byte[] realKey = new byte[formattedDecrKey.length - 3];
            System.arraycopy(formattedDecrKey, 1, realKey, 0, realKey.length);
            //BigInteger test = new BigInteger(realKey);
            //String hexKey = test.toString(16);
            //int hc = hexKey.hashCode();
            SecretKeySpec ks = new SecretKeySpec(realKey, "DESede");
            Des decryptor = new Des(ks);
            decryptor.decrypt(PGPFile, outputFile);
            outputFile.close();
        } else
            System.out.println("Decrypt: can't find PKESKP packet");
        PGPFile.close();
    }
}

class Program {
    public static void main(String[] argv) throws Exception {
        PGPcreator crtr = new PGPcreator();
        //Both digital signature and confidentiality services may be applied to
        //the same message.  First, a signature is generated for the message
        //and attached to the message.  Then the message plus signature is
        //encrypted using a symmetric session key.  Finally, the session key is
        //encrypted using public-key encryption and prefixed to the encrypted
        //block.

        //3.  The sending software generates a signature from the hash code
        //using the sender's private key.
        //4.  The binary signature is attached to the message.
        //5.  The receiving software keeps a copy of the message signature.
        //6.  The receiving software generates a new hash code for the received
        //message and verifies it using the message's signature.  If the
        //verification is successful, the message is accepted as authentic.
        //crtr.sign("test.txt", "encrypted_test.txt");
        crtr.encrypt("test.txt", "encrypted_test.txt");
        PGPcreator crtr2 = new PGPcreator();
        crtr2.decrypt("decrypted_test.txt", "encrypted_test.txt");
        //crtr2.checkSign("decrypted_test.txt", "encrypted_test.txt");
    }
}



