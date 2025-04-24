import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES {

    private SecretKey clave;
    private IvParameterSpec vector;

    public AES(byte[] claveCompartida) throws Exception {
        generarClave(claveCompartida);
    }

    public void generarClave(byte[] claveCompartida) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(claveCompartida);
        this.clave = new SecretKeySpec(Arrays.copyOfRange(hash, 0, 16), "AES");
    }

    public void generarVector() {
        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        this.vector = new IvParameterSpec(ivBytes);
    }

    public byte[] cifrar(byte[] datos) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clave, vector);
        return cipher.doFinal(datos);
    }

    public byte[] descifrar(byte[] datosCifrados) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, clave, vector);
        return cipher.doFinal(datosCifrados);
    }
} 