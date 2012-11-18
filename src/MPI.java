import java.io.FileOutputStream;
import java.io.RandomAccessFile;

public class MPI {
    byte[] MPI_len = new byte[2];
    byte[] MPI_string;

    MPI(byte[] string) {
        MPI_string = string;
        //byte[] len_in_bits = Utilities.toBytes(MPI_string.length * 8);
        int len_in_bits = 8 * (string.length - 1) + Utilities.BitsInByte(string[0]);
        // Damned Big-Endian
        byte[] len_to_write = Utilities.toBytes(len_in_bits);
        MPI_len[0] = len_to_write[2];
        MPI_len[1] = len_to_write[3];
        /*MPI_len[0] = len_in_bits[2];
        MPI_len[1] = len_in_bits[3]; */
    }

    MPI(RandomAccessFile in) throws Exception {
        byte[] len = new byte[4];
        if (in.read(MPI_len, 0, 2) != -1) {
            len[0] = len[1] = 0;
            //len[2] = MPI_len[1];
            //len[3] = MPI_len[0];
            len[2] = MPI_len[0];
            len[3] = MPI_len[1];
        } else
            throw new Exception("Can't read MPI length");
        //i tut!!
        MPI_string = new byte[Utilities.toInt(len) / 8];
        // /8+7 ili kakaya-to takaia hren!
        if (in.read(MPI_string, 0, Utilities.toInt(len) / 8) < 0)
            throw new Exception("Can't read MPI string");
    }

    public int len() {
        return MPI_string.length;
    }

    public void dump(FileOutputStream out) throws Exception {
        for (int i : MPI_len)
            out.write(i & 0xff);
        for (int i : MPI_string)
            out.write(i & 0xff);
    }
}