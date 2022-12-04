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

/**
 * CODE REFRENCE @web http://java-buddy.blogspot.com/
 */
public class JavaSSLServer {
    
    //static final int port = 7020;
    static final Map<String, String> mapOfUserPass = new HashMap<>();
    static final Map<String, Double> mapOfUserBalance = new HashMap<>();    
    static final Map<String, byte[]> mapOfIV = new HashMap<>(); 
    public static void main(String[] args) {
        
        int port = -1;
        generateRSAKeyPairAndStoreInFile();
        System.setProperty("javax.net.ssl.keyStore", "mykeystore/trusted.examplekeystore");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        String currUser = "";
        readPasswdFile();
        //System.out.println("args size : "+args.length);
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
            ServerSocket sslServerSocket = 
                    sslServerSocketFactory.createServerSocket(port);
            System.out.println("SSL ServerSocket started");
            System.out.println(sslServerSocket.toString());
            
            Socket socket = sslServerSocket.accept();
            System.out.println("ServerSocket accepted");
            
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String line;
                while((line = bufferedReader.readLine()) != null)
                {
                    //System.out.println("Msg from client = "+line);
                    if(line.indexOf("|") >= 0) //user credentials
                    {
                    String[] arr = line.split("\\|");
                    //out.println(encryptedSymmKey+"|"+userCredentailsCipherText);
                    String encryptedSymmKey = arr[0];
                    String userCredentailsCipherText = arr[1];
                    String decryptedSymmKey = decode(encryptedSymmKey);
                    //System.out.println("encryptedSymmKey = "+encryptedSymmKey);
                    //System.out.println("decryptedSymmKey = "+decryptedSymmKey);
                    
                    //IvParameterSpec ivParameterSpec = generateIv();
                    String aesAlgorithm = "AES/CBC/PKCS5Padding";
                    SecretKey secretKey = convertStringToSecretKeyto(decryptedSymmKey);
                    //byte[] iv = decryptedSymmKey.split("--")[1].getBytes(StandardCharsets.UTF_8);
                    byte[] iv = new byte[16];
                    if(!mapOfIV.containsKey("IV"))
                    {
                        DataInputStream dis = null;
                        dis = new DataInputStream(new FileInputStream(new File("paramFile")));
                        dis.readFully(iv);
                        if (dis != null) {
                            mapOfIV.put("IV",iv);
                            dis.close();
                        }
                    }
                    else
                        iv = mapOfIV.get("IV");
                    //System.out.println("iv.length = "+iv.length);
                    String idPass = decrypt(aesAlgorithm, userCredentailsCipherText, secretKey, new IvParameterSpec(iv));
                    //SHA1 reference : http://oliviertech.com/java/generate-SHA1-hash-from-a-String/
                    //String passwordSha1 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(idPass.split(" ")[1]);
                    String []user = idPass.split(" ");
                    currUser = user[0];
                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    digest.reset();
                    digest.update(user[1].getBytes("utf8"));
                    String passwordSha1 = String.format("%040x", new BigInteger(1, digest.digest()));
                    if(mapOfUserPass.containsKey(user[0]))
                    {
                        if(mapOfUserPass.get(user[0]).equals(passwordSha1))
                        {
                            
                            out.println("1"); //user valid
                        }
                        else
                            out.println("0"); //password incorrect

                    }
                    else
                        out.println("0"); //user not found in passwd file
                    
                    
                }
                else if(line.indexOf("~") >= 0){
                    String[] arr = line.split("~");
                    //out.println(encryptedSymmKey+"|"+userCredentailsCipherText);
                    String encryptedSymmKey = arr[0];
                    String balanceCipherText = arr[1];
                    String decryptedSymmKey = decode(encryptedSymmKey);
                    //System.out.println("encryptedSymmKey = "+encryptedSymmKey);
                    //System.out.println("decryptedSymmKey = "+decryptedSymmKey);
                    
                    //IvParameterSpec ivParameterSpec = generateIv();
                    String aesAlgorithm = "AES/CBC/PKCS5Padding";
                    SecretKey secretKey = convertStringToSecretKeyto(decryptedSymmKey);
                    //byte[] iv = decryptedSymmKey.split("--")[1].getBytes(StandardCharsets.UTF_8);
                    byte[] iv = new byte[16];
                    if(!mapOfIV.containsKey("IV"))
                    {
                        DataInputStream dis = null;
                        dis = new DataInputStream(new FileInputStream(new File("paramFile")));
                        dis.readFully(iv);
                        if (dis != null) {
                            mapOfIV.put("IV",iv);
                            dis.close();
                        }
                    }
                    else
                        iv = mapOfIV.get("IV");
                    //System.out.println("iv.length = "+iv.length);
                    String balanceStr = decrypt(aesAlgorithm, balanceCipherText, secretKey, new IvParameterSpec(iv));
                    arr = balanceStr.split(" ");
                    Double balOfCurrUser = getBalanceOfUser(currUser);
                    if(balOfCurrUser >= Double.parseDouble(arr[1]))
                    {
                        // mapOfUserBalance.put(currUser, mapOfUserBalance.get(currUser)-Double.parseDouble(arr[1]));
                        // mapOfUserBalance.put(arr[0], mapOfUserBalance.get(arr[0])+Double.parseDouble(arr[1]));
                        updateBalanceOfUser(currUser, balOfCurrUser - Double.parseDouble(arr[1]));
                        updateBalanceOfUser(arr[0], getBalanceOfUser(arr[0]) + Double.parseDouble(arr[1]));
                        out.println("1");
                    }
                    else{
                        out.println("0");
                    }
                }
                else//exit
                {
                    
                }
                    
            //System.out.println("Closed");
            
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
          //.filter(file -> !Files.isDirectory(file))
          .map(Path::getFileName)
          .map(Path::toString)
          .collect(Collectors.toSet());
    }  
   
}
    private static Double getBalanceOfUser(String user)
    {
        Double ret = 0.0;
        try
        {
        String file ="balance";
        
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        
            while((line = reader.readLine()) != null)
            {
                String [] userInfo = line.split(" ");
                if(userInfo.length == 2)
                    if(userInfo[0].equals(user))
                        {
                            ret = Double.parseDouble(userInfo[1]);
                            break;
                        }
           
            }
               
        
        reader.close();
        
        }
        catch(IOException ex)
        {
            Logger.getLogger(JavaSSLServer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        return ret;
    }

    private static void updateBalanceOfUser(String user, Double amount)
    {
        try
        {
        String file ="balance";
        StringBuilder oldContent = new StringBuilder();
        String userOldAmt = "";
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        
            while((line = reader.readLine()) != null)
            {
                if(line.split(" ")[0].equals(user))
                {
                    userOldAmt = line.split(" ")[1];
                }
                oldContent.append(line+System.lineSeparator());
            }
        String newContent = oldContent.toString().replace(user+" "+userOldAmt, user+" "+amount);
        FileWriter writer = new FileWriter(file);
        writer.write(newContent);
        
        reader.close();
        writer.close();
        
        }
        catch(IOException ex)
        {
            Logger.getLogger(JavaSSLServer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        
    }

    private static void readPasswdFile()
    {
        try
        {
        String file ="passwd";
     
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while((line = reader.readLine()) != null)
        {
            String [] user = line.split(":");
            if(user.length == 2)
                mapOfUserPass.put(user[0],user[1]);
        }
        System.out.println("In readPasswdFile --> map.get(alice) = "+mapOfUserPass.get("alice"));
        reader.close();
        }
        catch(IOException ex)
        {
            Logger.getLogger(JavaSSLServer.class.getName())
                    .log(Level.SEVERE, null, ex);
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
        System.out.println("In generateRSAKeyPairAndStoreInFile");
        
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

private PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // reading from resource folder
        //byte[] privateKeyBytes = getClass().getResourceAsStream("/ssh_key").readAllBytes();
        File privateKeyFile = new File("private.key");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = privateKeyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }
public static String decode(String toDecode) throws Exception {

        PrivateKey privateKey = new JavaSSLServer().loadPrivateKey();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(toDecode));
        return new String(bytes);

    }
    public static SecretKey convertStringToSecretKeyto(String encodedKey) {
    byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
    SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    return originalKey;
}
public static String decrypt(String algorithm, String cipherText, SecretKey key,IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException 
    {    
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
            .decode(cipherText));
        return new String(plainText);
    }
    
}