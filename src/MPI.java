import java.io.FileOutputStream;
import java.io.RandomAccessFile;

public class MPI {
    byte[] MPIlen = new byte[2];
    byte[] MPIstring;

    MPI(byte[] string) {
        MPIstring = string;
        //byte[] lenInBits = Utilities.toBytes(MPIstring.length * 8);
        int lenInBits = 8 * (string.length - 1) + Utilities.BitsInByte(string[0]);
        // Damned Big-Endian
        byte[] lenToWrite = Utilities.toBytes(lenInBits);
        MPIlen[0] = lenToWrite[2];
        MPIlen[1] = lenToWrite[3];
        /*MPIlen[0] = lenInBits[2];
        MPIlen[1] = lenInBits[3]; */
    }

    MPI(RandomAccessFile in) throws Exception {
        byte[] len = new byte[4];
        if (in.read(MPIlen, 0, 2) != -1) {
            len[0] = len[1] = 0;
            //len[2] = MPIlen[1];
            //len[3] = MPIlen[0];
            len[2] = MPIlen[0];
            len[3] = MPIlen[1];
        } else
            throw new Exception("Can't read MPI length");
        //i tut!!
        MPIstring = new byte[Utilities.toInt(len) / 8];
        // /8+7 ili kakaya-to takaia hren!
        if (in.read(MPIstring, 0, Utilities.toInt(len) / 8) < 0)
            throw new Exception("Can't read MPI string");
    }

    public int len() {
        return MPIstring.length;
    }

    public void dump(FileOutputStream out) throws Exception {
        for (int i : MPIlen)
            out.write(i & 0xff);
        for (int i : MPIstring)
            out.write(i & 0xff);
    }
}