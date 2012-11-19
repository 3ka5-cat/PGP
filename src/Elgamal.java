import java.math.BigInteger;

/**
 * Date: 19.11.12
 * Time: 2:49
 */
public class Elgamal {
    public static byte[] ElgamalEncrypt(String key, BigInteger y, BigInteger k, BigInteger p) throws Exception {
        BigInteger m = new BigInteger(key, 16);
        //encrypt c = (m + y^k)(mod p)
        BigInteger c = m.add(y.modPow(k, p)).mod(p);
        return Utilities.toBytes(c);
    }

    public static byte[] ElgamalDecrypt(String key, String base, BigInteger x, BigInteger p) throws Exception {
        BigInteger c = new BigInteger(key, 16);
        BigInteger a = new BigInteger(base, 16);
        //decrypt  m = (c - a^x)(mod p)
        BigInteger m = c.subtract(a.modPow(x, p)).mod(p);
        return Utilities.toBytes(m);
    }
}
