import java.math.BigInteger;

public class ECPoint
{
    public BigInteger x;
    public BigInteger y;
    public BigInteger a;
    public BigInteger b;
    public BigInteger FieldChar;

    public ECPoint(ECPoint p)
    {
        x = p.x;
        y = p.y;
        a = p.a;
        b = p.b;
        FieldChar = p.FieldChar;
    }

    public ECPoint()
    {
    }
    //сложение двух точек P1 и P2
    public static ECPoint Add(ECPoint p1, ECPoint p2)
    {
        ECPoint p3 = new ECPoint();
        p3.a = p1.a;
        p3.b = p1.b;
        p3.FieldChar = p1.FieldChar;

        BigInteger dy = p2.y.subtract(p1.y);
        BigInteger dx = p2.x.subtract(p1.x);

        if (dx.compareTo(BigInteger.ZERO) < 0)
            dx = dx.add(p1.FieldChar);
        if (dx.compareTo(BigInteger.ZERO) < 0)
            dy = dy.add(p1.FieldChar);

        BigInteger m = (dy.multiply(dx.modInverse(p1.FieldChar))).remainder(p1.FieldChar);
        if (m.compareTo(BigInteger.ZERO) < 0)
            m = m.add(p1.FieldChar);
        BigInteger mSquare = m.multiply(m);
        p3.x = (mSquare.subtract(p1.x).subtract(p2.x)).remainder(p1.FieldChar);
        p3.y = ((m.multiply(p1.x.subtract(p3.x))).subtract(p1.y)).remainder(p1.FieldChar);
        if (p3.x.compareTo(BigInteger.ZERO) < 0)
            p3.x = p3.x.add(p1.FieldChar);
        if (p3.y.compareTo(BigInteger.ZERO) < 0)
            p3.y = p3.y.add(p1.FieldChar);
        return p3;
    }
    //сложение точки P c собой же
    public static ECPoint Double(ECPoint p)
    {
        ECPoint p2 = new ECPoint();
        p2.a = p.a;
        p2.b = p.b;
        p2.FieldChar = p.FieldChar;

        BigInteger dy = BigInteger.valueOf(3).multiply(p.x).multiply(p.x).add(p.a);
        BigInteger dx = BigInteger.TWO.multiply(p.y);

        if (dx.compareTo(BigInteger.ZERO) < 0)
            dx = dx.add(p.FieldChar);
        if (dy.compareTo(BigInteger.ZERO) < 0)
            dy = dy.add(p.FieldChar);

        BigInteger m = (dy.multiply(dx.modInverse(p.FieldChar))).remainder(p.FieldChar);
        p2.x = (m.multiply(m).subtract(p.x).subtract(p.x)).remainder(p.FieldChar);
        p2.y = (m.multiply(p.x.subtract(p2.x)).subtract(p.y)).remainder(p.FieldChar);
        if (p2.x.compareTo(BigInteger.ZERO) < 0)
            p2.x = p2.x.add(p.FieldChar);
        if (p2.x.compareTo(BigInteger.ZERO) < 0)
            p2.y = p2.y.add(p.FieldChar);

        return p2;
    }
    //умножение точки на число x, по сути своей представляет x сложений точки самой с собой
    public static ECPoint multiply(BigInteger x, ECPoint p)
    {
        ECPoint temp = p;
        x = x.subtract(BigInteger.ONE);
        while (!x.equals(BigInteger.ZERO))
        {

            if ((!x.remainder(BigInteger.TWO).equals(BigInteger.ZERO)))
            {
                if ((temp.x.equals(p.x)) || (temp.y.equals(p.y)))
                    temp = Double(temp);
                else
                    temp = Add(temp, p);
                x = x.subtract(BigInteger.ONE);
            }
            x = x.divide(BigInteger.TWO);
            p = Double(p);
        }
        return temp;
    }
}
