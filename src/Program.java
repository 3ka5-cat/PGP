class Program {
    public static void main(String[] argv) throws Exception {
        /*
        RSAcreator crtr = new RSAcreator();
        //Both digital signature and confidentiality services may be applied to
        //the same message.  First, a signature is generated for the message
        //and attached to the message.  Then the message plus signature is
        //encrypted using a symmetric session key.  Finally, the session key is
        //encrypted using public-key encryption and prefixed to the encrypted
        //block.

        //3.  The sending software generates a signature from the hash code
        //using the sender's private key.
        //4.  The binary signature is attached to the message.
        //5.  The receiving software keeps a copy of the message signature.
        //6.  The receiving software generates a new hash code for the received
        //message and verifies it using the message's signature.  If the
        //verification is successful, the message is accepted as authentic.
        //crtr.sign("test.txt", "encrypted_test.txt");
        crtr.encrypt("test.txt", "encrypted_test.txt");
        RSAcreator crtr2 = new RSAcreator();
        crtr2.decrypt("decrypted_test.txt", "encrypted_test.txt");
        //crtr2.checkSign("decrypted_test.txt", "encrypted_test.txt");
        */

        ElgamalCreator crtr = new ElgamalCreator(256);
        crtr.encrypt("test.txt", "encrypted_test.txt",256);
        crtr.decrypt("decrypted_test.txt", "encrypted_test.txt");

    }
}