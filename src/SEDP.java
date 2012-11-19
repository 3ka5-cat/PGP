import java.io.FileOutputStream;

/**
 * Date: 19.11.12
 * Time: 3:36
 */
public class SEDP implements Constants {
    // Symmetrically Encrypted Data Packet
    // ------ header -----
    // C3 -- packet tag -- Symmetrically Encrypted Data Packet
    byte packet_tag;
    byte packet_length;
    // ------ data ------
    // 04 -- Version
    // 02 -- Symmetric-Key Algorithm ID -- TripleDES
    // S2K reserved...
    // encrypted data
    byte version;
    byte key_id;
    byte s2k;
    byte[] cipher_text;

    SEDP(byte[] data, byte len) throws Exception {
        packet_tag = (byte) SEDP_TAG;
        version = 4;
        key_id = (byte) TRIPLEDES_ID;
        s2k = (byte) S2K_reserved;
        cipher_text = data;
        packet_length = (byte) (len + 1 + 1 + 1);  // padded data + version + sym_alg_id + S2K
    }

    public void dump(FileOutputStream out) throws Exception {
        out.write(packet_tag & 0xff);
        out.write(packet_length & 0xff);
        out.write(version & 0xff);
        out.write(key_id & 0xff);
        out.write(s2k & 0xff);
        out.write(cipher_text, 0, packet_length);
    }
}
