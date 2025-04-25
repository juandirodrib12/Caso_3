import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class RSA {

    private PrivateKey clavePrivada;
    private PublicKey clavePublica;

    public void generarClaves() throws Exception {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(1024);
        KeyPair parLlaves = generador.generateKeyPair();

        PrivateKey llavePrivada = parLlaves.getPrivate();
        PublicKey llavePublica = parLlaves.getPublic();
        Files.createDirectories(Paths.get("claves"));

        try (FileOutputStream privOut = new FileOutputStream("claves/clave_privada.key")) {
            privOut.write(llavePrivada.getEncoded());
        }
        try (FileOutputStream pubOut = new FileOutputStream("claves/clave_publica.key")) {
            pubOut.write(llavePublica.getEncoded());
        }
    }

    public void cargarClavePrivada() throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get("claves/clave_privada.key")));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        this.clavePrivada = factory.generatePrivate(spec);
    }

    public void cargarClavePublica() throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Files.readAllBytes(Paths.get("claves/clave_publica.key")));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        this.clavePublica = factory.generatePublic(spec);
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

    public PrivateKey obtenerClavePrivada() {
        return this.clavePrivada;
    }

    public PublicKey obtenerClavePublica() {
        return this.clavePublica;
    }
}