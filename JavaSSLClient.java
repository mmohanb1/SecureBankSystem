import java.io.BufferedReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.io.File;
import java.io.FileReader;
import java.security.KeyPairGenerator;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.nio.file.Files;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocketFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * CODE REFRENCE @web http://java-buddy.blogspot.com/
 */
public class JavaSSLClient {
    
    //static final int port = 7020;

    public static void main(String[] args) {
        int port = -1;
        String domain = "";
        System.setProperty("javax.net.ssl.trustStore", "mykeystore/trusted.examplekeystore");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        String currUser;
        
        if(args != null && args.length > 0){
            if(args[0] != null){
                System.out.println("Server Domain : "+args[0]);
                domain = args[0];
            }
            else
            {
                System.out.println("*****************Please enter domain*****************");
                System.exit(0);
            }
            if(args[1] != null){
                System.out.println("Port : "+args[1]);
                port = Integer.parseInt(args[1]);
            }
            else
            {
                System.out.println("*****************Please enter port*****************");
                System.exit(0);
            }

        }
        else
        {
            System.out.println("*****************Please enter domain and port*****************");
            System.exit(0);
        }
        SSLSocketFactory sslSocketFactory = 
                (SSLSocketFactory)SSLSocketFactory.getDefault();
        try {
            
            Socket socket = sslSocketFactory.createSocket(domain, port);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                Scanner scanner = new Scanner(System.in);

                System.out.println("Enter UserID:");
                String userId = scanner.nextLine();
                currUser = userId;
                System.out.println("Enter Password:");
                String userPassword = scanner.nextLine();
                //reference to ASAsymmetric key encryption and decryption : https://www.baeldung.com/java-aes-encryption-decryption
                //reference to RSA encryption and decryption : https://gustavopeiretti.com/rsa-encrypt-decrypt-java/

                //1. generate symmetric key and encrypt the id, password using symmetric key
                String idPass = userId+" "+userPassword;


                //byte[] iv = new byte[16];
                byte[] iv = { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 };
                
                SecretKey aesSymmetricKey = generateKey(128);
                
                String aesAlgorithm = "AES/CBC/PKCS5Padding";
                String userCredentailsCipherText = encrypt(aesAlgorithm, idPass, aesSymmetricKey, new IvParameterSpec(iv));
                

                //2. encrypt the symmetric key & iv bytes using public key
                String strAesSymmetricKey = convertSecretKeyToString(aesSymmetricKey);
                String encryptedSymmKey = encode(strAesSymmetricKey);                
                
                //3. send the data to bank server
                out.println(encryptedSymmKey+"|"+userCredentailsCipherText);

                //4. get the message from bank server
                String serverResponse;
                while((serverResponse = bufferedReader.readLine()).equals("0")){
                    System.out.println("UserId and/or Password incorrect, please enter correct user details:");
                    System.out.println("-------------------------------------------------------------------");
                    System.out.println("Enter UserID:");
                    userId = scanner.nextLine();
                    currUser = userId;
                    System.out.println("Enter Password:");
                    userPassword = scanner.nextLine();
                    idPass = userId+" "+userPassword;
                    userCredentailsCipherText = encrypt(aesAlgorithm, idPass, aesSymmetricKey, new IvParameterSpec(iv));
                    encryptedSymmKey = encode(strAesSymmetricKey);                
                    
                    out.println(encryptedSymmKey+"|"+userCredentailsCipherText);
                }
                
                while(true){
                    
                    System.out.println("Your Account balance is "+getBalanceOfUser(currUser));
                    
                    System.out.println("-------------------------------------------------------------------");
                    System.out.println("1. Transfer");
                    System.out.println("2. Exit");
                    String option = scanner.nextLine();
                    if(option.equals("1"))
                    {
                        System.out.println("Please enter the userId to which the money is to be transferred:");
                        userId = scanner.nextLine();
                        if(userId.equals(currUser))
                            {
                                System.out.println("***Please enter valid userId***");
                                continue;
                            }
                        System.out.println("Please enter the amount to be transferred:");
                        String amt = scanner.nextLine();
                        String userBalanceTranferCipherText = encrypt(aesAlgorithm, userId+" "+amt, aesSymmetricKey, new IvParameterSpec(iv));
                        out.println(encryptedSymmKey+"~"+userBalanceTranferCipherText);
                        serverResponse = bufferedReader.readLine();
                        if(serverResponse != null){                            
                            if(serverResponse.equals("0"))
                                System.out.println("Your transaction was unsuccesfull.");
                            else
                                System.out.println("Your transaction was succesfull.");
                        }
                    }
                    else if(option.equals("2")) //exit
                    {
                        out.println("2");
                        
                        socket.close();
                        break;

                    }
                    else
                    {
                        System.out.println("Please enter valid option.");
                    }
                }
                bufferedReader.close();
                out.close();
            
            
        } catch (Exception ex) {
            Logger.getLogger(JavaSSLClient.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
         
    }
    public static String convertSecretKeyToString(SecretKey secretKey) throws NoSuchAlgorithmException {
    byte[] rawData = secretKey.getEncoded();
    String encodedKey = Base64.getEncoder().encodeToString(rawData);
    return encodedKey;
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

    public static String encrypt(String algorithm, String input, SecretKey key,IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException 
    {    
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
            .encodeToString(cipherText);
    }

    

    private PublicKey loadPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // reading from resource folder
        
        File publicKeyFile = new File("public.key");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = publicKeyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    

    public static String encode(String toEncode) throws Exception {

        
        PublicKey publicKey = new JavaSSLClient().loadPublicKey();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = cipher.doFinal(toEncode.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(bytes));
    }    
    
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}