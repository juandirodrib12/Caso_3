import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

public class HMAC {

    public static SecretKeySpec derivarClave(byte[] claveBytes) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(claveBytes);
        return new SecretKeySpec(Arrays.copyOfRange(hash, 16, 32), "HmacSHA256");
    }

    public static byte[] generar(byte[] datos, SecretKeySpec claveHMAC) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(claveHMAC);
        return mac.doFinal(datos);
    }

    public static boolean verificar(byte[] datos, byte[] recibido, SecretKeySpec claveHMAC) throws Exception {
        byte[] esperado = generar(datos, claveHMAC);
        return Arrays.equals(esperado, recibido);
    }
}