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
public class ElgamalCreator {
    //params
    BigInteger g;
    BigInteger p;
    // keys
    BigInteger y;   //public
    BigInteger x;   //private
    SecretKey key;  //3des
    // ciphertext
    BigInteger c;
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
        System.out.println("P: " + p.toString());
        if (m.compareTo(p) == -1) {
            System.out.println("Key: " + m.toString());
            //encrypt c = (m + y^k)(mod p)
            c = m.add(y.modPow(k, p)).mod(p);
            Des encryptor = new Des(key);
            encryptor.encrypt(input_file, PGP_file);
        } else System.out.println("Too big session key");
        input_file.close();
        PGP_file.close();
    }

    public void decrypt(String file, String encrypted_file) throws Exception {
        RandomAccessFile PGP_file = new RandomAccessFile(encrypted_file, "r");
        FileOutputStream output_file = new FileOutputStream(file, true);
        //decrypt  m = (c - a^x)(mod p)
        BigInteger key = c.subtract(a.modPow(x, p)).mod(p);
        System.out.println("Decrypted key: " + key.toString());
        SecretKeySpec ks = new SecretKeySpec(key.toByteArray(), "DESede");
        Des decryptor = new Des(ks);
        decryptor.decrypt(PGP_file, output_file);
        output_file.close();
        PGP_file.close();
    }
}