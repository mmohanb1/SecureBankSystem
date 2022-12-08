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
public class ClientHandler implements Runnable
{
    private Socket socket;
    private PrintWriter out;
    private BufferedReader bufferedReader;
    private final Map<String, String> mapOfUserPass = new HashMap<>();

    public ClientHandler(Socket clientSocket) throws IOException
    {
        this.socket = clientSocket;
        this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.out = new PrintWriter(socket.getOutputStream(), true);
        readPasswdFile();
    }

    public void run()
    {
        try{
               String line;
               String currUser = "";
                while((line = bufferedReader.readLine()) != null)
                {
                    
                    if(line.indexOf("|") >= 0) //user credentials
                    {
                    String[] arr = line.split("\\|");
                    
                    String encryptedSymmKey = arr[0];
                    String userCredentailsCipherText = arr[1];
                    String decryptedSymmKey = decode(encryptedSymmKey);
                    
                    String aesAlgorithm = "AES/CBC/PKCS5Padding";
                    SecretKey secretKey = convertStringToSecretKeyto(decryptedSymmKey);
                    
                    byte[] iv = { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 };
                    String idPass = decrypt(aesAlgorithm, userCredentailsCipherText, secretKey, new IvParameterSpec(iv));
                    //SHA1 reference : http://oliviertech.com/java/generate-SHA1-hash-from-a-String/
                    
                    String []user = idPass.split(" ");
                    currUser = user[0];
                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    digest.reset();
                    digest.update(user[1].getBytes("utf8"));
                    String passwordSha1 = String.format("%040x", new BigInteger(1, digest.digest()));
                    if(this.mapOfUserPass.containsKey(user[0]))
                    {
                        if(this.mapOfUserPass.get(user[0]).equals(passwordSha1))
                        {
                            
                            out.println("1"); //user valid
                        }
                        else
                            out.println("0"); //password incorrect

                    }
                    else
                        out.println("0"); //user not found in passwd file
                    
                    
                }
                if(line.indexOf("~") >= 0){
                    String[] arr = line.split("~");
                    
                    String encryptedSymmKey = arr[0];
                    String balanceCipherText = arr[1];
                    String decryptedSymmKey = decode(encryptedSymmKey);
                    
                    String aesAlgorithm = "AES/CBC/PKCS5Padding";
                    SecretKey secretKey = convertStringToSecretKeyto(decryptedSymmKey);
                    
                    byte[] iv = { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 };
                    
                    String balanceStr = decrypt(aesAlgorithm, balanceCipherText, secretKey, new IvParameterSpec(iv));
                    arr = balanceStr.split(" ");
                    Double balOfCurrUser = getBalanceOfUser(currUser);
                    if(balOfCurrUser >= Double.parseDouble(arr[1]))
                    {
                        
                        Path file = Paths.get("passwd");
                        // read all lines of the file
                        long countLines = Files.lines(file).count();
                        
                        if(countLines > this.mapOfUserPass.size())
                        {
                            readPasswdFile();
                        }
                        if(this.mapOfUserPass.containsKey(arr[0])){
                        Double balOfUser = getBalanceOfUser(arr[0]);
                        
                            updateBalanceOfUser(currUser, balOfCurrUser - Double.parseDouble(arr[1]));
                            updateBalanceOfUser(arr[0], getBalanceOfUser(arr[0]) + Double.parseDouble(arr[1]));
                            out.println("1");
                        }
                        else
                            out.println("0");
                    }
                    else{
                        out.println("0");
                    }
                }
                if(line.equals("2"))//exit
                {
                    socket.close();
                    break;
                }
                    
            //System.out.println("Closed");
            
        }
        bufferedReader.close();
        out.close();
        }
        catch(Exception ex)
        {
            Logger.getLogger(JavaSSLServer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
    }
    private Double getBalanceOfUser(String user)
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

    private void updateBalanceOfUser(String user, Double amount)
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

    private void readPasswdFile()
    {
        try
        {
        String file ="passwd";
     
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while((line = reader.readLine()) != null)
        {
            String [] user = line.split(" ");
            if(user.length == 2)
                this.mapOfUserPass.put(user[0],user[1]);
        }
        //System.out.println("In readPasswdFile --> map.get(alice) = "+this.mapOfUserPass.get("alice"));
        reader.close();
        }
        catch(IOException ex)
        {
            Logger.getLogger(JavaSSLServer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
    }
private String decode(String toDecode) throws Exception {

        PrivateKey privateKey = loadPrivateKey();

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
private PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // reading from resource folder
        
        File privateKeyFile = new File("private.key");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = privateKeyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }
private String decrypt(String algorithm, String cipherText, SecretKey key,IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
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