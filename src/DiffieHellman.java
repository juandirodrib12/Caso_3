import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.spec.DHParameterSpec;

public class DiffieHellman {
  
    private BigInteger base;
    private BigInteger modulo;
    private BigInteger claveSecreta;
    private BigInteger clavePublica;
    private byte[] claveCompartida;

    public DiffieHellman() throws Exception {
        AlgorithmParameterGenerator generador = AlgorithmParameterGenerator.getInstance("DH");
        generador.init(1024);
        AlgorithmParameters parametros = generador.generateParameters();
        DHParameterSpec dhSpec = parametros.getParameterSpec(DHParameterSpec.class);

        this.base = dhSpec.getG();
        this.modulo = dhSpec.getP();
        generarClaveSecreta();
    }

    public DiffieHellman(BigInteger base, BigInteger modulo) {
        this.base = base;
        this.modulo = modulo;
        generarClaveSecreta();
    }

    public void generarClaveSecreta() {
        SecureRandom random = new SecureRandom();
        this.claveSecreta = new BigInteger(modulo.bitLength() - 1, random);
    }

    public void generarClavePublica() {
        this.clavePublica = base.modPow(claveSecreta, modulo);
    }

    public void generarClaveCompartida(BigInteger claveRecibida) {
        this.claveCompartida = claveRecibida.modPow(claveSecreta, modulo).toByteArray();
    }

    public byte[] generarHash() throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-512");
        byte[] hash = sha.digest(claveCompartida);
        return hash;
    }

    public BigInteger obtenerBase() {
        return this.base;
    }

    public BigInteger obtenerModulo() {
        return this.modulo;
    }

    public BigInteger obtenerClavePublica() {
        return this.clavePublica;
    }
}