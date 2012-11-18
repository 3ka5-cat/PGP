import java.math.BigInteger;

public class RSA {
    public static byte[] RSAoperation(String key, String exp, String modulus) throws Exception {
        BigInteger e = new BigInteger(exp, 16);
        BigInteger n = new BigInteger(modulus, 16);
        BigInteger m = new BigInteger(key, 16);

        BigInteger encrypted_m = m.modPow(e, n);
        return Utilities.toBytes(encrypted_m);
    }
}
