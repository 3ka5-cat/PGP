/**
 * Created with IntelliJ IDEA.
 * User: cat
 * Date: 11.09.12
 * Time: 19:10
 * To change this template use File | Settings | File Templates.
 */
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class PGPcreator {
    SecretKey key;
    String pub_exp;
    String mod;
    String priv_exp;

    PGPcreator() throws Exception
    {   //DESede -- Triple DES Encryption
        //key = KeyGenerator.getInstance("DESede").generateKey();

        byte[] keyBytes = "0123456789ABCDEFABCDEF01234567890123456789ABCDEF".getBytes("ASCII");
        DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
        key = factory.generateSecret(keySpec);
        //String format = key.getFormat();
        //System.out.println(format);
        pub_exp = "10001";
        mod = "9EB288221963C9639A3F5F4CA71DD3831660F92F0AE38FFC0A1C593E19B35750E2A297E4B7EEA75037DB15C754D56B214849BD7E452880789F0B98CCB82044FB54ECA34769E66973CC4747BB38DBC58417937F035DBA96DCE331E713AE3FF7BCC9BCCB4CFEAFF29A8A258F9CF151B2BE26E88784FA22BE3145390A9DCEA509F3";
        priv_exp = "28B52D1C6A1CE1ACEE053181ED2046804ABE474D1CE2F0AD3B3EB859A8A80B4ED143D9E8AE91C6535A70956E93414780BB1547495B9E1F0E51E5DCA52EDA00377A382AEF528959EB8D4C5BABE3C47104790FFB21DA4248FE1B1D07B194E76E7D80FF21A515D1DA5D7DF72C766BF556EB406765669598932B22133D97355138E1";

    }
    public void encrypt(String file, String encrypted_file) throws Exception
    {
        FileInputStream input_file = new FileInputStream(file);
        FileOutputStream PGP_file = new FileOutputStream(encrypted_file);
        PKESKP key_packet = new PKESKP(key, pub_exp, mod);
        key_packet.dump(PGP_file);
        //byte[] encr_key = RSA.RSA_operation(Utilities.getHexString(key.getEncoded()), pub_exp, mod);
        Des encryptor = new Des(key);
        encryptor.encrypt(input_file, PGP_file);
    }

    public void decrypt(String file, String encrypted_file) throws Exception
    {
        FileInputStream PGP_file = new FileInputStream(encrypted_file);
        FileOutputStream output_file = new FileOutputStream(file);
        PKESKP key_packet=new PKESKP(PGP_file);
        byte[] formatted_decr_key = RSA.RSA_operation(Utilities.getHexString(key_packet.encrKey.MPIstring), priv_exp, mod);
        byte[] real_key=new byte[formatted_decr_key.length - 3];
        System.arraycopy(formatted_decr_key,1,real_key,0,real_key.length);
        //BigInteger test = new BigInteger(real_key);
        //String hex_key = test.toString(16);
        //int hc = hex_key.hashCode();
        SecretKeySpec ks = new SecretKeySpec(real_key, "DESede");
        Des decryptor = new Des(ks);
        decryptor.decrypt(PGP_file, output_file);
    }
}

class Ugly_JAVA {
    public static void main(String[] argv) throws Exception {
        PGPcreator crtr = new PGPcreator();
        crtr.encrypt("test.txt","encrypted_test.txt");
        crtr.decrypt("decrypted_test.txt","encrypted_test.txt");
    }
}



