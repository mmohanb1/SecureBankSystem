import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.File;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.net.ServerSocket;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.net.Socket;
import java.util.logging.Level;
import java.security.spec.EncodedKeySpec;
import java.util.logging.Logger;
import javax.net.ssl.SSLServerSocketFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.util.stream.*;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.security.KeyFactory;
import java.util.Map;
import java.util.HashMap;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.FileOutputStream;
import java.security.KeyPairGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

/**
 * CODE REFRENCE @web http://java-buddy.blogspot.com/
 */
public class JavaSSLServer {
    
    private static List<ClientHandler> lisOfClientHandlers = new ArrayList<>(); 
    private static ExecutorService pool = Executors.newFixedThreadPool(100);
    public static void main(String[] args) {
        
        int port = -1;
        generateRSAKeyPairAndStoreInFile();
        System.setProperty("javax.net.ssl.keyStore", "mykeystore/trusted.examplekeystore");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        
        if(args != null && args.length > 0){
            if(args[0] != null){
                System.out.println("Port : "+args[0]);
                port = Integer.parseInt(args[0]);
            }
            else
            {
                System.out.println("*****************Please enter port to run the server*****************");
                System.exit(0);
            }

        }
        else
        {
            System.out.println("*****************Please enter port to run the server*****************");
            System.exit(0);
        }
        SSLServerSocketFactory sslServerSocketFactory = 
                (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
        
        try {
            ServerSocket sslServerSocket = sslServerSocketFactory.createServerSocket(port);
            System.out.println("SSL ServerSocket started");
            System.out.println(sslServerSocket.toString());
            while(!sslServerSocket.isClosed())
            {
            Socket client = sslServerSocket.accept();
            System.out.println("ServerSocket accepted");
            ClientHandler clientThread = new ClientHandler(client);
            lisOfClientHandlers.add(clientThread);
            pool.execute(clientThread);
            
            }
        }
         catch (Exception ex) {
            Logger.getLogger(JavaSSLServer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
    }
    //below function reference : https://www.baeldung.com/java-list-directory-files
    public static Set<String> listFilesUsingFilesList(String dir) throws IOException {
    try (Stream<Path> stream = Files.list(Paths.get(dir))) {
        return stream
          
          .map(Path::getFileName)
          .map(Path::toString)
          .collect(Collectors.toSet());
    }  
   
}
    
    private static void generateRSAKeyPairAndStoreInFile()
    {
        try{
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        
        
        try (FileOutputStream fos = new FileOutputStream("public.key")) 
        {
            fos.write(publicKey.getEncoded());
        }
        
        catch (Exception ex) {
            Logger.getLogger(JavaSSLClient.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        try (FileOutputStream fos = new FileOutputStream("private.key")) 
        {
            fos.write(privateKey.getEncoded());
        }
        
        catch (Exception ex) {
            Logger.getLogger(JavaSSLClient.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        }
        catch(Exception ex)
        {
            Logger.getLogger(JavaSSLClient.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        
    }


   
}