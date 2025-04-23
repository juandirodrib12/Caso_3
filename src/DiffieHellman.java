import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {

    public static BigInteger generarNumeroAleatorio(BigInteger p) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(p.bitLength() - 1, random);
    }

    public static BigInteger calcularValorCompartido(BigInteger g, BigInteger x, BigInteger p) {
        return g.modPow(x, p);
    }

    public static byte[] obtenerClaveCompartida(BigInteger claveCompartida) {
        return claveCompartida.toByteArray();
    }
}