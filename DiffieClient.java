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
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;




public class DiffieClient {




    private int sPort             = 0;
    private Key mClientPublicKey  = null;
    private Key mClientPrivateKey = null;
    private KeyPair mKeyPair      = null;
    private DataInputStream in    = null;
    private DataOutputStream out  = null;
    private Key mCommonKey        = null;
    private KeyAgreement mKeyAgreement = null;



    private Socket sock = null;
    private Key serverPubKey = null;



    public DiffieClient(int port){

        this.sPort = port;
        this.initSocketConnection();

    }


    private void initSocketConnection(){


        // Initialise server connection
        try{
            sock = new Socket("127.0.0.1", 9999);
        } catch (UnknownHostException e) {
            System.out.println("Unknown host: " + e.getMessage());
            System.exit(1);
        } catch  (IOException e) {
            e.printStackTrace(System.out);
            System.exit(1);
        }

        this.exchangeKeysAndConverse();

    }

    private void exchangeKeysAndConverse(){

        // Get server pub key
        try{
            byte[] lenb = new byte[4];
            sock.getInputStream().read(lenb,0,4);

            ByteBuffer bb = ByteBuffer.wrap(lenb);

            int len = bb.getInt();

            System.out.println(len);

            byte[] servPubKeyBytes = new byte[len];

            // Get the server public key from the socket.
            sock.getInputStream().read(servPubKeyBytes);

            //
            X509EncodedKeySpec ks = new X509EncodedKeySpec(servPubKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("DH");

            serverPubKey = kf.generatePublic(ks);

            System.out.println("Server Public Key: "+DatatypeConverter.printHexBinary(serverPubKey.getEncoded()));
            System.err.println("");
            System.err.println("");


            // Now Generate the client key pair.



            System.out.println("[*] Generating Key Pair....");
            try {

                KeyPairGenerator DHKeyGen = KeyPairGenerator.getInstance("DH");
                DHKeyGen.initialize(512);
                mKeyPair = DHKeyGen.generateKeyPair();
                mClientPublicKey = mKeyPair.getPublic();
                mClientPrivateKey = mKeyPair.getPrivate();
                System.err.println("[*] Key Pair Generated. Public Key is: " + DatatypeConverter.printHexBinary(mClientPublicKey.getEncoded()));
                System.err.println("");
                System.err.println("");
                System.err.println("[*] Private Key is: " + DatatypeConverter.printHexBinary(mClientPrivateKey.getEncoded()));
                System.err.println("");
                System.err.println("");

            } catch (GeneralSecurityException gse){
                System.err.println("General Sec Exception: " + gse.getMessage());
            }


            // Send the server out public key.
            out = new DataOutputStream(sock.getOutputStream());
            ByteBuffer cb = ByteBuffer.allocate(4);
            cb.putInt(mClientPublicKey.getEncoded().length);

            out.write(cb.array());
            out.write(mClientPublicKey.getEncoded());
            out.flush();



            /**
             * Now generate a a common secret key.
             **/
            try {
                mKeyAgreement = KeyAgreement.getInstance("DH");
                mKeyAgreement.init(mClientPrivateKey);
                mKeyAgreement.doPhase(serverPubKey,true);
                mCommonKey = mKeyAgreement.generateSecret("AES");

                System.out.println("[*] Ths common key is: " + DatatypeConverter.printHexBinary(mCommonKey.getEncoded()));



                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

                cipher.init(Cipher.DECRYPT_MODE, mCommonKey);

                byte[] buf = new byte[64];

                ObjectOutputStream obj_out = new ObjectOutputStream( sock.getOutputStream() );
                ObjectInputStream  obj_in  = new ObjectInputStream( sock.getInputStream() );
                BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ));

                System.out.println("[*] Connected to the server...waiting for message from server.");
                while(true){


                    cipher.init(Cipher.DECRYPT_MODE, mCommonKey);
                    byte[] incoming_message = (byte[]) obj_in.readObject();
                    byte[] newPlainText = cipher.doFinal(incoming_message);

                    System.out.println("[*] Server data> " + new String( newPlainText, "UTF8"));
                    System.out.print("[*] Client data> ");
                    cipher.init(Cipher.ENCRYPT_MODE, mCommonKey);

                    String message = stdIn.readLine();
                    byte[] plainTextMessage = message.getBytes("UTF8");
                    byte[] encrypted_message = cipher.doFinal(plainTextMessage);
                    obj_out.writeObject(encrypted_message);
                    obj_out.flush();

                }


            } catch (Exception e){
                e.printStackTrace(System.out);
            }
        } catch (IOException e) {
            System.out.println("Error obtaining server public key 1.");
            System.exit(0);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error obtaining server public key 2.");
            System.exit(0);
        } catch (InvalidKeySpecException e) {
            System.out.println("Error obtaining server public key 3.");
            System.exit(0);
        }


        try {
            sock.close();
        } catch(Exception e){
            System.err.println(e.getMessage());
        }


    }





    public static void main(String args[]){

        System.out.println("Starting the DiffieClient...");
        DiffieClient client = new DiffieClient(9999);








    }

}