import java.math.BigInteger;

/**
 * Created with IntelliJ IDEA.
 * User: cat
 * Date: 15.10.12
 * Time: 21:12
 * To change this template use File | Settings | File Templates.
 */
public class RSA {
    public static byte[] RSA_operation(String key, String exp, String modulus) throws Exception {
        BigInteger e = new BigInteger(exp, 16);
        BigInteger n = new BigInteger(modulus, 16);
        BigInteger m = new BigInteger(key, 16);

        BigInteger encrypted_m = m.modPow(e,n);
        return Utilities.toBytes(encrypted_m);
    }
}
