import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Date: 18.11.12
 * Time: 18:57
 */
public class ElgamalCreator implements Constants {
    //params
    BigInteger g;
    BigInteger p;
    // keys
    BigInteger y;   //public
    BigInteger x;   //private
    SecretKey key;  //3des
    // ciphertext
    BigInteger a;

    ElgamalCreator(int size) throws Exception {
        key = KeyGenerator.getInstance("DESede").generateKey();
        generateParams(size);
    }

    public void generateParams(int size) throws Exception {
        SecureRandom rnd = new SecureRandom();
        //generate params
        do {
            g = new BigInteger(size, rnd);
            p = BigInteger.probablePrime(size, rnd);
        } while (g.modPow(p.subtract(BigInteger.ONE), p).compareTo(BigInteger.ONE) != 0);
        //generate keys
        do
            x = new BigInteger(size, rnd);
        while (x.compareTo(p.subtract(BigInteger.ONE)) != -1 && x.compareTo(BigInteger.ONE) != 1);
        y = g.modPow(x, p);
    }

    public void encrypt(String file, String encrypted_file, int size) throws Exception {
        FileInputStream input_file = new FileInputStream(file);
        FileOutputStream PGP_file = new FileOutputStream(encrypted_file, true);
        SecureRandom rnd = new SecureRandom();
        //session key k, must be 1<k<p-1
        BigInteger k;
        do
            k = new BigInteger(size, rnd);
        while (k.compareTo(p.subtract(BigInteger.ONE)) != -1 && k.compareTo(BigInteger.ONE) != 1);
        a = g.modPow(k, p);
        BigInteger m = new BigInteger(key.getEncoded());
        if (m.compareTo(p) == -1) {
            System.out.println("Key: " + Utilities.getHexString(m.toByteArray()));
            ElgamalPKESKP keyPacket = new ElgamalPKESKP(key, a, y, k, p);
            keyPacket.dump(PGP_file);
            Des encryptor = new Des(key);
            encryptor.encrypt(input_file, PGP_file);
        } else System.out.println("Too big session key");
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
            FileOutputStream output_file = new FileOutputStream(file, true);
            ElgamalPKESKP key_packet = new ElgamalPKESKP(PGP_file);
            byte[] formatted_decr_key =
                    Elgamal.ElgamalDecrypt(Utilities.getHexString(key_packet.encr_key.MPI_string),
                            Utilities.getHexString(key_packet.base.MPI_string), x, p);
            formatted_decr_key = PKCS1.decrypt(formatted_decr_key);
            byte[] real_key = new byte[formatted_decr_key.length - 3];
            System.arraycopy(formatted_decr_key, 1, real_key, 0, real_key.length);
            System.out.println("Decrypted key: " + Utilities.getHexString(real_key));
            if (formatted_decr_key[0] == TRIPLEDES_ID) {
                SecretKeySpec ks = new SecretKeySpec(real_key, "DESede");
                Des decryptor = new Des(ks);
                decryptor.decrypt(PGP_file, output_file);
            } else
                System.out.println("Decrypt Elgamal PKESKP: id of symmetric encryption algorithm used to encrypt " +
                        "data isn't TripleDES");
            output_file.close();
        } else
            System.out.println("Decrypt: can't find PKESKP packet");
        PGP_file.close();
    }

}