import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

public class Cliente {

    private int idCliente;
    private int numConsultas;

    public Cliente(int idCliente, int numConsultas) {
        this.idCliente = idCliente;
        this.numConsultas = numConsultas;
    }

    public void ejecutar() {
        try (
            Socket socket = new Socket("localhost", 5000);
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        ) {
            int consultasRealizadas = 0;

            while (consultasRealizadas < numConsultas) {
                consultasRealizadas++;

                // Paso 1: Se manda "HELLO"
                salida.println("HELLO");
                System.out.println("Cliente " + idCliente + " (consulta " + consultasRealizadas + "): envio HELLO");

                // Paso 2: Generar y mandar reto
                SecureRandom random = new SecureRandom();
                int retoGenerado = random.nextInt(1000000);
                salida.println(retoGenerado);
                System.out.println("Cliente " + idCliente + " (consulta " + consultasRealizadas + "): envio reto -> " + retoGenerado);

                // Esperar la respuesta cifrada del servidor 
                String respuestaCifrada = entrada.readLine();
                System.out.println("Cliente " + idCliente + " (consulta " + consultasRealizadas + "): recibio respuesta cifrada -> " + respuestaCifrada);
                byte[] respuestaCifradaBytes = Base64.getDecoder().decode(respuestaCifrada);

                // Paso 5a: Se descifra el reto 
                RSA rsa = new RSA();
                rsa.cargarClavePublica();
                PublicKey clavePublicaServidor = rsa.obtenerClavePublica();
                byte[] retoDescifradoBytes = RSA.descifrarConPublica(respuestaCifradaBytes, clavePublicaServidor);
                String retoDescifrado = new String(retoDescifradoBytes, "UTF-8");
                System.out.println("Cliente " + idCliente + " (consulta " + consultasRealizadas + "): reto descifrado -> " + retoDescifrado);

                // Paso 5b: Se compara el reto recibido con el enviado 
                if (Integer.parseInt(retoDescifrado) == retoGenerado) {
                    System.out.println("Cliente " + idCliente + " (consulta " + consultasRealizadas + "): reto verificado correctamente.");
                    // Paso 6 OK
                    salida.println("OK");
                } else {
                    System.out.println("Cliente " + idCliente + " (consulta " + consultasRealizadas + "): error en la verificación del reto.");
                    // Paso 6 ERROR
                    salida.println("ERROR");
                }

                // Paso 8 Leer G, P, G^x y la firma 
                String Gstr = entrada.readLine();
                String Pstr = entrada.readLine();
                String Gxstr = entrada.readLine();
                String firmaBase64 = entrada.readLine();

                System.out.println("Cliente " + idCliente + ": recibió G, P, G^x y firma");

                // Convertir G, P, G^x a BigInteger
                BigInteger G = new BigInteger(Gstr);
                BigInteger P = new BigInteger(Pstr);
                BigInteger Gx = new BigInteger(Gxstr);

                // Decodificar la firma de Base64
                byte[] firmaRecibida = Base64.getDecoder().decode(firmaBase64);

                // Se juntan como el mensaje que firmo el servidor
                String datosParaVerificar = G.toString() + "|" + P.toString() + "|" + Gx.toString();
                byte[] datosBytes = datosParaVerificar.getBytes("UTF-8");

                // Paso 9 se verifica la firma
                boolean firmaValida = RSA.verificarFirma(datosBytes, firmaRecibida, clavePublicaServidor);
                if (firmaValida) {
                    System.out.println("Cliente " + idCliente + ": firma de parámetros verificada correctamente.");
                    // Paso 10 OK
                    salida.println("OK");
                } else {
                    System.out.println("Cliente " + idCliente + ": error en la verificación de la firma de parámetros.");
                    // Paso 10 ERROR
                    salida.println("ERROR");
                }

                // Paso 11a Cliente genera su propio par Diffie-Hellman y envía G^y

                // Crear el objeto DiffieHellman usando G y P recibidos
                DiffieHellman dhCliente = new DiffieHellman(G, P);

                // Generar su secreto (y) y (G^y)
                dhCliente.generarClavePublica();
                BigInteger Gy = dhCliente.obtenerClavePublica();

                // Enviar G^y al servidor
                salida.println(Gy.toString());
                System.out.println("Cliente " + idCliente + ": envió G^y -> " + Gy.toString());

                dhCliente.generarClaveCompartida(Gx);
                System.out.println("Cliente " + idCliente + ": clave compartida generada.");

                byte[] hashClaveCompartida = dhCliente.generarHash();

                // primeros 32 bytes para AES, últimos 32 bytes para HMAC
                byte[] llaveAES = new byte[32];
                byte[] llaveHMAC = new byte[32];
                System.arraycopy(hashClaveCompartida, 0, llaveAES, 0, 32);
                System.arraycopy(hashClaveCompartida, 32, llaveHMAC, 0, 32);

                System.out.println("Cliente " + idCliente + ": llaves derivadas (AES y HMAC)");

                // Paso 12a: Generar IV aleatorio
                SecureRandom bytesrandom = new SecureRandom();
                byte[] iv = new byte[16];
                bytesrandom.nextBytes(iv);

                System.out.println("Cliente " + idCliente + ": IV generado.");

                // Se envia IV al servidor
                String ivBase64 = Base64.getEncoder().encodeToString(iv);
                salida.println(ivBase64);
                System.out.println("Cliente " + idCliente + ": IV enviado al servidor.");

            }

        } catch (Exception e) {
            System.out.println("Error en el cliente " + idCliente + ": " + e.getMessage());
        }
    }
}
