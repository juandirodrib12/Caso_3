import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.Base64;

public class ServidorDelegado implements Runnable {

    private Socket socket;
    private int idDelegado;

    public ServidorDelegado(Socket socket, int idDelegado) {
        this.socket = socket;
        this.idDelegado = idDelegado;
    }

    @Override
    public void run() {
        try (
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);
        ) {
            // Paso 1 se recibe "HELLO"
            String mensaje = entrada.readLine();
            System.out.println("Delegado " + idDelegado + " recibió: " + mensaje);

            if ("HELLO".equals(mensaje)) {
                // Paso 2: Esperar el reto enviado por el cliente
                String retoStr = entrada.readLine();
                System.out.println("Delegado " + idDelegado + " recibió reto: " + retoStr);

                // Convertir reto a bytes
                byte[] retoBytes = retoStr.getBytes("UTF-8");

                // Paso 3 Cifrar el reto con la llave privada
                RSA rsa = new RSA();
                rsa.cargarClavePrivada(); 
                PrivateKey clavePrivada = rsa.obtenerClavePrivada();

                byte[] retoCifrado = RSA.cifrarConPrivada(retoBytes, clavePrivada); 
                String retoCifradoBase64 = Base64.getEncoder().encodeToString(retoCifrado);

                // Paso 4 se envia la respuesta cifrada al cliente
                salida.println(retoCifradoBase64);
                System.out.println("Delegado " + idDelegado + " envió la respuesta cifrada.");
                
                // Se acaba la comunicacion si el cliente manda error 
                String respuestaCliente = entrada.readLine();
                if ("ERROR".equals(respuestaCliente)) {
                    System.out.println("Error en la consulta");
                    socket.close(); 
                    return;
                }
                // Paso 7 se genera parámetros de Diffie-Hellman
                DiffieHellman dh = new DiffieHellman(); 
                dh.generarClavePublica();

                // Obtener los valores G, P, G^x
                BigInteger G = dh.obtenerBase();
                BigInteger P = dh.obtenerModulo();
                BigInteger Gx = dh.obtenerClavePublica();

                // Paso 8 Mandar G, P, G^x y Firmar
                // Se juntan para firmarlos
                String datosParaFirmar = G.toString() + "|" + P.toString() + "|" + Gx.toString();
                byte[] datosBytes = datosParaFirmar.getBytes("UTF-8");

                byte[] firma = RSA.firmar(datosBytes, clavePrivada);
                String firmaBase64 = Base64.getEncoder().encodeToString(firma);

                salida.println(G.toString());
                salida.println(P.toString());
                salida.println(Gx.toString());
                salida.println(firmaBase64);

                System.out.println("Delegado " + idDelegado + ": envió G, P, G^x y firma al cliente.");

                // Paso 10 
                String respuestaCliente2 = entrada.readLine();
                if ("ERROR".equals(respuestaCliente2)) {
                    System.out.println("Error en la consulta");
                    socket.close(); 
                    return;
                }

                // Paso 11b: Recibir G^y (clave pública del cliente)
                String GyStr = entrada.readLine();
                BigInteger Gy = new BigInteger(GyStr);
                System.out.println("Delegado " + idDelegado + ": recibió G^y -> " + Gy.toString());

                // Paso 12a: Recibir IV
                String ivBase64 = entrada.readLine();
                byte[] iv = Base64.getDecoder().decode(ivBase64);
                System.out.println("Delegado " + idDelegado + ": recibió IV del cliente.");

                // Paso 11b se calcula la clave compartida
                dh.generarClaveCompartida(Gy);
                System.out.println("Delegado " + idDelegado + ": clave compartida generada.");
                byte[] hashClaveCompartida = dh.generarHash();

                byte[] llaveAES = new byte[32];
                byte[] llaveHMAC = new byte[32];
                System.arraycopy(hashClaveCompartida, 0, llaveAES, 0, 32);
                System.arraycopy(hashClaveCompartida, 32, llaveHMAC, 0, 32);

                System.out.println("Delegado " + idDelegado + ": llaves derivadas (AES y HMAC)");



            }
        } catch (Exception e) {
            System.out.println("Error en el delegado " + idDelegado + ": " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (Exception e) {
                System.out.println("Error al cerrar socket del delegado " + idDelegado);
            }
        }
    }
}
