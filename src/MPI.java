import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created with IntelliJ IDEA.
 * User: cat
 * Date: 15.10.12
 * Time: 21:07
 * To change this template use File | Settings | File Templates.
 */
public class MPI {
    byte[] MPIlen = new byte[2];
    byte[] MPIstring;
    MPI(byte[] string)
    {
        MPIstring = string;
        byte[] len_in_bits = Utilities.toBytes(MPIstring.length * 8);
        int t = MPIstring.length * 8;
        // Damned Big-Endian
        MPIlen[0] = len_in_bits[3];
        MPIlen[1]  = len_in_bits[2];
    }
    MPI(InputStream in) throws Exception
    {
        byte[] len= new byte[4];
        in.read((byte[])MPIlen,0,2);
        len[0]=len[1]=0;
        len[2]=MPIlen[1];
        len[3]=MPIlen[0];
        MPIstring=new byte[Utilities.toInt(len)/8];
        in.read(MPIstring,0,Utilities.toInt(len)/8);
    }
    public int len() {
        return MPIstring.length;
    }
    public void dump(OutputStream out) throws Exception{
        for(int i : MPIlen)
            out.write(i & 0xff);
        for(int i : MPIstring)
            out.write(i & 0xff);
    }
}