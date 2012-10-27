import java.io.FileOutputStream;
import java.io.RandomAccessFile;

public class MPI {
    byte[] MPIlen = new byte[2];
    byte[] MPIstring;
    MPI(byte[] string)
    {
        MPIstring = string;
        byte[] len_in_bits = Utilities.toBytes(MPIstring.length * 8);
        // Damned Big-Endian
        MPIlen[0] = len_in_bits[3];
        MPIlen[1] = len_in_bits[2];
    }
    MPI(RandomAccessFile in) throws Exception
    {
        byte[] len = new byte[4];
        if (in.read(MPIlen,0,2) != -1) {
            len[0] = len[1] = 0;
            len[2] = MPIlen[1];
            len[3] = MPIlen[0];
        }
        else
            throw new Exception("Can't read MPI length");
        MPIstring = new byte[Utilities.toInt(len)/8];
        if (in.read(MPIstring, 0, Utilities.toInt(len)/8) < 0)
            throw new Exception("Can't read MPI string");
    }
    public int len() {
        return MPIstring.length;
    }
    public void dump(FileOutputStream out) throws Exception{
        for(int i : MPIlen)
            out.write(i & 0xff);
        for(int i : MPIstring)
            out.write(i & 0xff);
    }
}