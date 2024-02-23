import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;

public class ECDH {
    private final String name;
    private final BigInteger p;

    private final BigInteger a;

    private final BigInteger b;

    private final BigInteger[] g;

    private final BigInteger n;

    private final BigInteger h;

    public ECDH(String name, BigInteger p, BigInteger a, BigInteger b, BigInteger[] g, BigInteger n, BigInteger h){
        this.name = name;
        this.p = p;
        this.a = a;
        this.b = b;
        this.g = g;
        this.n = n;
        this.h = h;
    }

    public ECDH(){
        this.name = "secp256k1";
        this.p = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16);
        this.a = BigInteger.ZERO;
        this.b = BigInteger.valueOf(7);
        this.g = new BigInteger[]{
                new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
                new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)};
        this.n = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
        this.h = BigInteger.ONE;

    }

    public BigInteger[] Add(BigInteger[] p1, BigInteger[] p2)
    {
        BigInteger[] p3 = new BigInteger[2];

        BigInteger dy = p2[1].subtract(p1[1]);
        BigInteger dx = p2[0].subtract(p1[0]);

        if (dx.compareTo(BigInteger.ZERO) < 0){
            dx = dx.add(p);
        }

        if (dx.compareTo(BigInteger.ZERO) < 0)
            dy = dy.add(p);

        BigInteger m = (dy.multiply(dx.modInverse(p))).remainder(p);
        if (m.compareTo(BigInteger.ZERO) < 0)
            m = m.add(p);
        BigInteger mSquare = m.multiply(m);
        p3[0] = (mSquare.subtract(p1[0]).subtract(p2[0])).remainder(p);
        p3[1] = ((m.multiply(p1[0].subtract(p3[0]))).subtract(p1[1])).remainder(p);
        if (p3[0].compareTo(BigInteger.ZERO) < 0)
            p3[0] = p3[0].add(p);
        if (p3[1].compareTo(BigInteger.ZERO) < 0)
            p3[1] = p3[1].add(p);
        return p3;
    }

    public BigInteger[] Double(BigInteger[] p)
    {

        BigInteger dy = BigInteger.valueOf(3).multiply(p[0]).multiply(p[0]).add(a);
        BigInteger dx = BigInteger.TWO.multiply(p[1]);

        if (dx.compareTo(BigInteger.ZERO) < 0)
            dx = dx.add(this.p);
        if (dy.compareTo(BigInteger.ZERO) < 0)
            dy = dy.add(this.p);

        BigInteger m = (dy.multiply(dx.modInverse(this.p))).remainder(this.p);
        BigInteger[] p2 = new BigInteger[2];
        p2[0] = (m.multiply(m).subtract(p[0]).subtract(p[0])).remainder(this.p);
        p2[1] = (m.multiply(p[0].subtract(p2[0])).subtract(p[1])).remainder(this.p);
        if (p2[0].compareTo(BigInteger.ZERO) < 0)
            p2[0] = p2[0].add(this.p);
        if (p2[1].compareTo(BigInteger.ZERO) < 0)
            p2[1] = p2[1].add(this.p);

        return p2;
    }

    public BigInteger[] scalarMultiply(BigInteger x, BigInteger[] point)
    {
        BigInteger[] temp = point;
        x = x.subtract(BigInteger.ONE);
        while (!x.equals(BigInteger.ZERO))
        {

            if ((!x.remainder(BigInteger.TWO).equals(BigInteger.ZERO)))
            {
                if ((temp[0].equals(point[0])) || (temp[1].equals(point[1])))
                    temp = Double(temp);
                else
                    temp = Add(temp, point);
                x = x.subtract(BigInteger.ONE);
            }
            x = x.divide(BigInteger.TWO);
            point = Double(point);
        }
        return temp;
    }

    public BigInteger makePrivateKey(){
        BigInteger privateKey = BigInteger.probablePrime(n.bitLength(), new Random());
        while(privateKey.signum() != 1 && privateKey.compareTo(n) >= 0){
            privateKey = BigInteger.probablePrime(n.bitLength(), new Random());
        }
        return privateKey;
    }

    public BigInteger[] makeKeyPair(BigInteger privateKey){

        return scalarMultiply(privateKey, g);
    }

    public byte[] hashMessage(byte[] message, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(salt);
        return md.digest(message);
    }

    public byte[] getSalt(){
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public BigInteger[] signMessage(BigInteger privateKey, byte[] hash) throws NoSuchAlgorithmException {
        BigInteger alpha = new BigInteger(1, hash);
        BigInteger e = alpha.remainder(n);
        if (e.equals(BigInteger.ZERO)) e = BigInteger.ONE;
        BigInteger r = BigInteger.ZERO, s = BigInteger.ZERO;
        BigInteger k = BigInteger.valueOf(-2);
        while(r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO)) {
            while ((k.compareTo(BigInteger.ZERO) <= 0) || (k.compareTo(n) >= 0)) {
                k = BigInteger.probablePrime(n.bitCount(), new Random());
            }
            BigInteger[] C = scalarMultiply(k, g);
            r = C[0].remainder(n);
            s = ((r.multiply(privateKey)).add(k.multiply(e))).remainder(n);
        }
        return new BigInteger[]{r, s};
    }

    public boolean verifySignature(BigInteger[] publicKey, byte[] hash, BigInteger[] signature) throws NoSuchAlgorithmException {
        BigInteger r = signature[0];
        BigInteger s = signature[1];
        if ((r.compareTo(BigInteger.ONE) < 0) || (r.compareTo(n.subtract(BigInteger.ONE)) > 0) || (s.compareTo(BigInteger.ONE) < 0) || (s.compareTo(n.subtract(BigInteger.ONE)) > 0))
            return false;
        BigInteger alpha = new BigInteger(1,hash);
        BigInteger e = alpha.remainder(n);
        if (e.equals(BigInteger.ZERO)) e = BigInteger.ONE;
        BigInteger v = e.modInverse(n);
        BigInteger z1 = (s.multiply(v)).remainder(n);
        BigInteger z2 = n.add(((r.multiply(v)).negate()).remainder(n));
        BigInteger[] A = scalarMultiply(z1, g);
        BigInteger[] B = scalarMultiply(z2, publicKey);
        BigInteger[] C = Add(A, B);
        BigInteger R = C[0].remainder(n);
        return R.equals(r);
    }
}