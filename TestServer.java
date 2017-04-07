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





public class TestServer {

/*    private void sendPublicKey(Key pubKey, Socket cClient){
        
        
         // Send public key
        try {
        System.out.println(DatatypeConverter.printHexBinary(pubKey.getEncoded()));

            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(pubKey.getEncoded().length);
            cClient.getOutputStream().write(bb.array());
            cClient.getOutputStream().write(pubKey.getEncoded());
            cClient.getOutputStream().flush();
        } catch (IOException e) {
            System.out.println("I/O Error");
            System.exit(0);
        }
        
        
    } */
    public static void main(String[] args) {
        

        if(args.length == 0 || args == null){
            System.out.println("Usage is: java TestServer <port number> <IP Address>");
            System.exit(0);
        }
        final int servPort = 9999;
        final int RSAKeySize = 512;
        final String newline = "\n";

        Key pubKey = null;
        Key mServerPrivateKey = null;
    	Key mCommonKey = null;
        ServerSocket cServer = null;
        Socket cClient = null;
        DataInputStream in;
        DataOutputStream out;
    	Key mClientKey;
        KeyAgreement mKeyAgreement = null;

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

        // Initialise socket connection
        try{
            cServer = new ServerSocket(servPort); 
            cClient = cServer.accept();


        } catch (IOException e) {
            System.out.println("Error initialising I/O.\n");
          
            System.exit(0);
            
        } 
        
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
                System.out.println("[*] Server data> " + message);

                cipher.init(Cipher.ENCRYPT_MODE, mCommonKey);

                byte[] plainTextMessage = message.getBytes("UTF8");
                byte[] encrypted_message = cipher.doFinal(plainTextMessage);
                obj_out.writeObject( encrypted_message );
                obj_out.flush();


            cipher.init(Cipher.DECRYPT_MODE, mCommonKey);

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


		/**
		 * Grab up to here.
		 */
		try {
			cServer.close();
        } catch (Exception e){
            System.out.println(e.getMessage());
            
        }
    }

}

