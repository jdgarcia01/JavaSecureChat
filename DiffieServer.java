/**
 * Author: John Garcia
 * Dependencies: JDK 1.8.0 plus the UnllimitedJCEpolicy files.  These JCE files are
 * located at: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
 * The new policies required to get around the key size limitation that some countries impose on their
 * serfs.
 *
 */




import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyAgreement;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;



public class DiffieServer {


    private int servPort = 9999;
    private int RSAKeySize = 512;
    private Key pubKey = null;
    private Key mServerPrivateKey = null;
    private Key mCommonKey = null;
    private ServerSocket cServer = null;
    private Socket cClient = null;
    private DataInputStream in;
    private DataOutputStream out;
    private Key mClientKey;
    private KeyAgreement mKeyAgreement = null;
    private String newline = "\n";


    public DiffieServer(int port, int key_size ){


        System.out.println("[*] Listening a port: " + port);
       System.out.println("[*] Init the key pair");
        // generate the key pairs that we need.
        this.generateKeyPairs();

        // initialize the socket.

       System.out.println("[*] Init the socket connection and wait for a client to connect...");
       this.initSocketConnection();


    }

    /**
     * We will generate a key pair for the server...the client also performs the same
     * operation.  With a little modification we could use the users public private key
     * but we decided to make things as simple as possible.
     */
    private void generateKeyPairs(){

        // Initialise DH
        try{

            KeyPairGenerator RSAKeyGen = KeyPairGenerator.getInstance("DH");
            RSAKeyGen.initialize(RSAKeySize);
            KeyPair pair = RSAKeyGen.generateKeyPair();
            pubKey = pair.getPublic();
            mServerPrivateKey = pair.getPrivate();

        } catch (GeneralSecurityException e) {
            System.out.println(e.getLocalizedMessage() + newline);
            System.out.println("Error initialising encryption. Exiting.\n");
            System.exit(0);
        }

    }


    /**
     * Nothing major here, just initialize a simple socket
     * and wait to accept a connection. Once a connection is
     * accepted we will send our public key with the client and
     * the client will send their public key to us, the server.
     *
     */

    private void initSocketConnection(){

        // Initialise socket connection
        try{
            cServer = new ServerSocket(servPort);
            cClient = cServer.accept();
            System.out.println("[*] Waiting for a connection");
            // exchange keys with the client and server.
            this.exchangeKeysAndConverse();

        } catch (IOException e) {
            System.out.println("Error initialising I/O.\n");

            System.exit(0);

        }

    }


    /**
     * This method does various tasks.  It will facilitate the
     * exchanging of public keys with the server and client and
     * also generating a common key for the server to use
     * for encryption and decryption.  The client performs the
     * same operation.
     */


    private void exchangeKeysAndConverse(){


        try {
            in = new DataInputStream(cClient.getInputStream());
            out = new DataOutputStream(cClient.getOutputStream());

            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(pubKey.getEncoded().length);


            /**
             * Write the public key to the client.
             */
            out.write(bb.array());
            out.write(pubKey.getEncoded());
            out.flush();

            /**
             * Get the public key from the client.
             */
            try {

                byte[] lenb = new byte[4];
                cClient.getInputStream().read(lenb, 0, 4);
                ByteBuffer cb = ByteBuffer.wrap(lenb);
                int len = cb.getInt();
                byte[] clientPubKeyBytes = new byte[len];
                cClient.getInputStream().read(clientPubKeyBytes);

                /**
                 * Format the byte array into the proper key format.
                 */
                X509EncodedKeySpec ks = new X509EncodedKeySpec(clientPubKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("DH");
                mClientKey = kf.generatePublic(ks);



                /**
                 * Generate a common secret key from the clients public and the servers
                 * private key.
                 */
                mKeyAgreement = KeyAgreement.getInstance("DH");
                mKeyAgreement.init(mServerPrivateKey);
                /**
                 * This is the common key that we will use to
                 * encrypt and decrypt data.
                 */
                mKeyAgreement.doPhase(mClientKey, true);
                mCommonKey = mKeyAgreement.generateSecret("AES");
                System.out.println("[*] Ths common key is: " + DatatypeConverter.printHexBinary(mCommonKey.getEncoded()));



                /**
                 *Ecypt a test string and send it to the client.
                 */
                String Text = "This is a test message";
                byte[] plainText = Text.getBytes("UTF8");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");


                /**System.out.println("Decrypting data....");
                 cipher.init(Cipher.DECRYPT_MODE, mCommonKey);
                 byte[] newPlainText = cipher.doFinal(cipherText);
                 System.out.println("Decrypted data: " + new String( newPlainText,"UTF8"));
                 */
                /**
                 *Send the test message to be decrypted on the other end of the pipe.
                 */

                ObjectOutputStream obj_out = new ObjectOutputStream( cClient.getOutputStream() );
                ObjectInputStream  obj_in  = new ObjectInputStream(  cClient.getInputStream());
                BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ));

                byte[] input = new byte[64];

                System.out.println("[*] Connected to the client....send a message");
                System.out.print("[*] Server data> ");
                while(true){



                    String message = stdIn.readLine();
//                    System.out.println("[*] Server data> " + message);

                    /**
                     * switch the cipher to encrypt mode, this is used to
                     * encrypt our text before sending it to the client.
                     */
                    cipher.init(Cipher.ENCRYPT_MODE, mCommonKey);

                    /**
                     * Format the text/message to UTF8.
                     */
                    byte[] plainTextMessage = message.getBytes("UTF8");

                    /**
                     * Encrypt the text/message
                     */
                    byte[] encrypted_message = cipher.doFinal(plainTextMessage);

                    /**
                     * Write the encrypted object to the buffer and flush the
                     * buffer.  The flush is needed to make sure we don't
                     * corrupt the sent message.
                     */
                    obj_out.writeObject( encrypted_message );
                    obj_out.flush();


                    /**
                     * switch our cipher to decrypt and incomping messages.
                     */
                    cipher.init(Cipher.DECRYPT_MODE, mCommonKey);

                    /**
                     * Read in the message, decrypt it and present it to the user.
                     */
                    byte[] incoming_message = (byte[]) obj_in.readObject();
                    byte[] newPlainText = cipher.doFinal(incoming_message);
                    System.out.println("[*] Client data> " + new String(newPlainText, "UTF8"));
                    System.out.print("[*] Server data> ");

                }


            } catch (Exception gse){

                System.err.println("Exception: " + gse.getMessage());
                gse.printStackTrace(System.out);
            }


        } catch (IOException e) {
            System.out.println("I/O Error");
            System.exit(0);
        }



    }

    /**
     * Used to cleanup any open connections when we encounter an error in our try/catch clauses.
     */
    private void cleanup(){

        try {
            cServer.close();
        } catch (Exception e){
            System.out.println(e.getMessage());

        }


    }
public static void main(String args[]){

    System.out.println("Starting the server...");
    System.out.println("Connected to port 9999");

    /**
     * you can change the port number and key size....make sure the changes
     * are made on the client side as well.
     */
    DiffieServer mainServer = new DiffieServer(9999,512);

    return;

}


}
