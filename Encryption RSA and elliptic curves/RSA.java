import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class RSA {
    private final BigInteger N;
    private final BigInteger e;
    private final BigInteger d;


    public RSA()
    {
        int BIT_LENGTH = 2048;
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH, new Random());
        BigInteger q = BigInteger.probablePrime(BIT_LENGTH, new Random());
        N = p.multiply(q);

        System.out.println(N.bitLength());
        BigInteger PHI = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e1 = new BigInteger("65537");

        while (!PHI.gcd(e1).equals(BigInteger.ONE) && e1.compareTo(PHI) < 0)
        {
            e1 = e1.add(BigInteger.ONE);
        }
        e = e1;
        d = e.modInverse(PHI);

//        System.out.println("(" + N + ", " + e + ")" + " - Открытый");
//        System.out.println("(" + N + ", " + d + ")" + " - Закрытый");
    }

    public RSA(int maxLength1)
    {
        Random r = new Random();
        BigInteger p = BigInteger.probablePrime(maxLength1, r);
        BigInteger q = BigInteger.probablePrime(maxLength1, r);
        N = p.multiply(q);
        System.out.println("Длина модуля N в битах - " + N.bitLength());
        BigInteger PHI = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        //BigInteger e1 = BigInteger.probablePrime(maxLength1/2, r);
        BigInteger e1 = new BigInteger("65537");
        while (!PHI.gcd(e1).equals(BigInteger.ONE) && e1.compareTo(PHI) < 0)
        {
            e1 = e1.add(BigInteger.ONE);
        }
        e = e1;
        d = e.modInverse(PHI);
    }

    // Encrypting the message
    public byte[] encryptMessage(byte[] message)
    {
        return (new BigInteger(1, message)).modPow(e, N).toByteArray();
    }

    // Decrypting the message
    public byte[] decryptMessage(byte[] message)
    {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }

    public BigInteger sign(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        BigInteger hash = new BigInteger(1,md.digest(message));
        return hash.modPow(d, N);
    }

    public boolean checkSign(byte[] message, BigInteger hash) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        BigInteger hashFromMessage = new BigInteger(1,md.digest(message));
        BigInteger hashFromFriend = hash.modPow(e, N);
        return hashFromFriend.equals(hashFromMessage);
    }
}
