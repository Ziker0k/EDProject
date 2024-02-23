import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] inputText = Files.readAllBytes(Path.of("text.txt"));
        System.out.println("######### RSA Realization #########");
        encryptAndDecryptWithRsa(inputText);
        System.out.println("######### End #########" + "\n");
        System.out.println("######### ECDH and ECDSA Realization #########");
        encryptAndDecryptWithECDHAndAES(inputText);
        System.out.println("######### End #########" + "\n");
    }

    public static void encryptAndDecryptWithECDHAndAES(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        ECDH ecdh = new ECDH();
        // Make private keys
//        BigInteger alicePrivateKey = ecdh.makePrivateKey();
//        BigInteger bobPrivateKey = ecdh.makePrivateKey();
        BigInteger alicePrivateKey = new BigInteger("2102");
        BigInteger bobPrivateKey = new BigInteger("610");

        // Make public keys
        BigInteger[] alicePublicKey = ecdh.makeKeyPair(alicePrivateKey);
        BigInteger[] bobPublicKey = ecdh.makeKeyPair(bobPrivateKey);

        //Make shared keys
        BigInteger[] sharedKey1 = ecdh.scalarMultiply(bobPrivateKey, alicePublicKey);
        BigInteger[] sharedKey2 = ecdh.scalarMultiply(alicePrivateKey, bobPublicKey);

        //Check if shared keys equals
        if(Arrays.equals(sharedKey1, sharedKey2)) {
            System.out.println("Общие ключи равны!");
        }else{
            throw new InvalidKeyException("Ключи не равны");
        }
        System.out.printf("Secret key is: (%s , %s)\n",
                sharedKey1[0].toString(16),
                sharedKey2[1].toString(16));
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(sharedKey1[0].toString(16).substring(0,16).getBytes(),"AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(bytes);
        writeBytesToFile("EncryptedWithECDHAndAES.txt", encryptedBytes);

        //Sign
        byte[] salt = ecdh.getSalt();
        byte[] hash = ecdh.hashMessage(encryptedBytes, salt);
        BigInteger[] signature = ecdh.signMessage(alicePrivateKey, hash);

        //Cipher with sharedKey and AES algo
        Cipher cipher1 = Cipher.getInstance("AES");
        cipher1.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] encryptedBytesFromFiles = readBytesFromFile("EncryptedWithECDHAndAES.txt");

        //Decryption
        byte[] decryptedBytes = cipher1.doFinal(encryptedBytesFromFiles);
        writeBytesToFile("DecryptedWithECDHAndAES.txt", decryptedBytes);

        //Check signature
        byte[] hash1 = ecdh.hashMessage(encryptedBytesFromFiles, salt);
        if(ecdh.verifySignature(alicePublicKey, hash1, signature)){
            System.out.println("Сообщение действительно от Алисы!");
        }else {
            System.out.println("Подпись неверна, сообщение было изменено, или пришло не от Алисы");
        }
    }

    public static void encryptAndDecryptWithRsa(byte[] bytes) throws NoSuchAlgorithmException, IOException {
        /* RSA */
        RSA rsa = new RSA(bytes.length * 4 + 1);
        System.out.println("Длина текста в битах - " + new BigInteger(bytes).bitLength());
        // Encrypting to byte array
        byte[] cipher = rsa.encryptMessage(bytes);
        // Writing byte array with encrypted info in secret file
        writeBytesToFile("EncryptedWithRSA.txt", cipher);
        // Hashing message
        BigInteger hash = rsa.sign(cipher);
        // Reading byte array from secret file
        byte[] cipherFromFile = readBytesFromFile("EncryptedWithRSA.txt");
        // Writing decrypted text to new txt file
        writeBytesToFile("DecryptedWithRSA.txt", rsa.decryptMessage(cipherFromFile));
        // Calculation of the message hash and comparison with the received hash associated with the message
        if(rsa.checkSign(cipherFromFile, hash)){
            System.out.println("Подпись верна, сообщение прислал Боб");
        }
    }

    public static byte[] readBytesFromFile(String path){
        try{
            return Files.readAllBytes(Path.of(path));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeBytesToFile(String path, byte[] myByteArray){
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(myByteArray);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
