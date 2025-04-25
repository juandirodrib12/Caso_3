import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class HMAC {

    private SecretKeySpec clave;

    public HMAC(byte[] hash) throws Exception {
        this.clave = generarClave(hash);
    }

    public static SecretKeySpec generarClave(byte[] hash) throws Exception {
        return new SecretKeySpec(Arrays.copyOfRange(hash, 32, 64), "HmacSHA256");
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