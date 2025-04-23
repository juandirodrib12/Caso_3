import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

public class AES {

    public static SecretKeySpec derivarClave(byte[] claveBytes) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(claveBytes);
        return new SecretKeySpec(Arrays.copyOfRange(hash, 0, 16), "AES");
    }

    public static byte[] cifrar(byte[] datos, SecretKeySpec claveAES) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, claveAES);
        return cipher.doFinal(datos);
    }

    public static byte[] descifrar(byte[] datosCifrados, SecretKeySpec claveAES) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, claveAES);
        return cipher.doFinal(datosCifrados);
    }
}