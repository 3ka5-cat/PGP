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
    BigInteger a;
    BigInteger p;
    // keys
    BigInteger b;   //public
    BigInteger x;   //private
    SecretKey key;  //3des
    // returned
    BigInteger c;
    BigInteger ay;

    ElgamalCreator(int size) throws Exception
    {
        key = KeyGenerator.getInstance("DESede").generateKey();
        generateParams(size);
    }
    public void generateParams(int size) throws Exception
    {
        SecureRandom rnd = new SecureRandom();
        //generate params
        do {
            a = new BigInteger(size,rnd);
            p = BigInteger.probablePrime(size,rnd);
        } while (a.modPow(p.subtract(BigInteger.ONE), p).compareTo(BigInteger.ONE) != 0);
        //generate keys
        x = new BigInteger(size,rnd);
        b = a.modPow(x, p);
    }
    public void encrypt(String file, String encrypted_file, int size) throws Exception
    {
        FileInputStream input_file = new FileInputStream(file);
        FileOutputStream PGP_file = new FileOutputStream(encrypted_file, true);
        SecureRandom rnd = new SecureRandom();
        BigInteger y = new BigInteger(size,rnd);
        ay = a.modPow(y,p);
        BigInteger by = b.modPow(y,p);
        //encrypt c = (m + b^y)(mod p)
        BigInteger m = new BigInteger(key.getEncoded());
        System.out.println("P: " + p.toString());
        System.out.println("Key BI: " + m.toString());
        if (m.compareTo(p) == -1) {
            System.out.println("Key: " + m.toString());
            c = (m.add(by)).mod(p);
            Des encryptor = new Des(key);
            encryptor.encrypt(input_file, PGP_file);
        }
        input_file.close();
        PGP_file.close();
    }
    public void decrypt(String file, String encrypted_file) throws Exception
    {
        RandomAccessFile PGP_file = new RandomAccessFile(encrypted_file,"r");
        FileOutputStream output_file = new FileOutputStream(file,true);
        BigInteger newby = ay.modPow(x,p);
        //decrypt  m = (c - b^y)(mod p)
        BigInteger newm = (c.subtract(newby)).mod(p);
        System.out.println("Decrypted key: " + newm.toString());
        SecretKeySpec ks = new SecretKeySpec(newm.toByteArray(), "DESede");
        Des decryptor = new Des(ks);
        decryptor.decrypt(PGP_file, output_file);
        output_file.close();
        PGP_file.close();
    }
}
