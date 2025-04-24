import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {
  
    private BigInteger base;
    private BigInteger modulo;
    private BigInteger claveSecreta;
    private BigInteger clavePublica;
    private byte[] claveCompartida;

    public DiffieHellman(BigInteger base, BigInteger modulo) {
        this.base = base;
        this.modulo = modulo;
        generarClaveSecreta(modulo);
    }

    public void generarClaveSecreta(BigInteger modulo) {
        SecureRandom random = new SecureRandom();
        this.claveSecreta = new BigInteger(modulo.bitLength() - 1, random);
    }

    public void generarClavePublica() {
        this.clavePublica = base.modPow(claveSecreta, modulo);
    }

    public void generarClaveCompartida(BigInteger claveRecibida) {
        this.claveCompartida = claveRecibida.modPow(claveSecreta, modulo).toByteArray();
    }

    public BigInteger obtenerClavePublica() {
        return this.clavePublica;
    }

    public byte[] obtenerClaveCompartida() {
        return this.claveCompartida;
    }
}