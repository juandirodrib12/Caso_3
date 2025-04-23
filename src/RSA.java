import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class RSA {

    private static KeyPair parLlaves;

    public static void generarLlaves() throws Exception {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        parLlaves = generador.generateKeyPair();
    }

    public static PrivateKey obtenerLlavePrivada() {
        return parLlaves.getPrivate();
    }

    public static PublicKey obtenerLlavePublica() {
        return parLlaves.getPublic();
    }

    public static byte[] firmar(byte[] datos, PrivateKey clavePrivada) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(clavePrivada);
        firma.update(datos);
        return firma.sign();
    }

    public static boolean verificarFirma(byte[] datos, byte[] firmaBytes, PublicKey clavePublica) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initVerify(clavePublica);
        firma.update(datos);
        return firma.verify(firmaBytes);
    }
}