import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES {

    private SecretKey clave;
    private IvParameterSpec vector;

    public AES(byte[] hash) throws Exception {
        generarClave(hash);
    }

    public void generarClave(byte[] hash) throws Exception {
        this.clave = new SecretKeySpec(Arrays.copyOfRange(hash, 0, 32), "AES");
    }

    public void generarVector() {
        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        this.vector = new IvParameterSpec(ivBytes);
    }

    public void generarVector(byte[] ivBytes) {
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

    public byte[] obtenerVector() {
        return this.vector.getIV();
    }
} 