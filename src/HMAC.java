import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

public class HMAC {

    private SecretKeySpec clave;

    public HMAC(byte[] claveCompartida) throws Exception {
        this.clave = generarClave(claveCompartida);
    }

    public static SecretKeySpec generarClave(byte[] claveCompartida) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(claveCompartida);
        return new SecretKeySpec(Arrays.copyOfRange(hash, 16, 48), "HmacSHA256");
    }

    public byte[] generarHash(byte[] datos) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(clave);
        return mac.doFinal(datos);
    }

    public boolean verificarHash(byte[] datos, byte[] hashRecibido) throws Exception {
        byte[] hashEsperado = generarHash(datos);
        return Arrays.equals(hashEsperado, hashRecibido);
    }
} 