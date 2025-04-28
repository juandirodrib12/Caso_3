import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Random;
import java.util.ArrayList;
import java.util.Base64;

public class Cliente extends Thread {

    private int id;
    private String ip;
    private int maximoSolicitudes;

    public Cliente(int id, int solicitudes) {
        this.id = id;
        this.ip = "192.168.1." + id;
        this.maximoSolicitudes = solicitudes;
    }

    @Override
    public void run() {

        try (
            Socket socket = new Socket("localhost", 5000);
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        ) {
            System.out.println("Cliente " + id + ": Conexión establecida con el servidor.");

            for (int i = 0; i < maximoSolicitudes; i++) {
                
                if (maximoSolicitudes > 1) {
                    System.out.println("Cliente " + id + ": Enviando consulta " + (i + 1) + " al servidor.");
                }
                else {
                    System.out.println("Cliente " + id + ": Enviando consulta al servidor.");
                }

                ejecutarProtocolo(socket, salida, entrada);
            }
        } 

        catch (Exception e) {
            System.out.println("Error en el cliente " + id + ": " + e.getMessage());
        }
    }

    public void ejecutarProtocolo(Socket socket, PrintWriter salida, BufferedReader entrada) {

        try {
            RSA rsa = new RSA();
            rsa.cargarClavePublica();
            PublicKey clavePublicaRSA = rsa.obtenerClavePublica();
            System.out.println("Cliente " + id + ": Clave pública cargada con éxito.");

            Random random = new Random();
            byte[] reto = new byte[48];
            random.nextBytes(reto);
            String retoBase64 = Base64.getEncoder().encodeToString(reto);
            salida.println(retoBase64);
            System.out.println("Cliente " + id + ": Reto enviado al servidor con éxito.");

            String firmaBase64 = entrada.readLine();
            byte[] firma = Base64.getDecoder().decode(firmaBase64);
            boolean verificacion = RSA.verificarFirma(reto, firma, clavePublicaRSA);

            System.out.println("Cliente " + id + ": Firma del reto recibida del servidor con éxito.");

            if (verificacion) {
                salida.println("OK");
                System.out.println("Cliente " + id + ": La verificación de la firma del reto ha sido exitosa.");
            } 
            else {
                salida.println("ERROR");
                throw new Exception("Cliente " + id + ": Error en la verificación de la firma del reto.");
            }

            BigInteger clavePublicaServidor = new BigInteger(entrada.readLine());
            BigInteger base = new BigInteger(entrada.readLine());
            BigInteger modulo = new BigInteger(entrada.readLine());
            System.out.println("Cliente " + id + ": Clave pública del servidor, base y módulo recibidos del servidor con éxito.");

            String firmaClavePublicaServidorBase64 = entrada.readLine();
            byte[] firmaClavePublicaServidor = Base64.getDecoder().decode(firmaClavePublicaServidorBase64);
            boolean verificacionClavePublicaServidor = RSA.verificarFirma(clavePublicaServidor.toByteArray(), firmaClavePublicaServidor, clavePublicaRSA);

            String firmaBaseBase64 = entrada.readLine();
            byte[] firmaBase = Base64.getDecoder().decode(firmaBaseBase64);
            boolean verificacionBase = RSA.verificarFirma(base.toByteArray(), firmaBase, clavePublicaRSA);

            String firmaModuloBase64 = entrada.readLine();
            byte[] firmaModulo = Base64.getDecoder().decode(firmaModuloBase64);
            boolean verificacionModulo = RSA.verificarFirma(modulo.toByteArray(), firmaModulo, clavePublicaRSA);

            System.out.println("Cliente " + id + ": Firmas de la clave pública del servidor, base y módulo recibidas del servidor con éxito.");

            if (verificacionClavePublicaServidor && verificacionBase && verificacionModulo) {
                salida.println("OK");
                System.out.println("Cliente " + id + ": La verificación de las firmas de la clave pública del servidor, base y módulo ha sido exitosa.");
            } 
            else {
                salida.println("ERROR");
                throw new Exception("Cliente " + id + ": Error en la verificación de las firmas de la clave pública del servidor, base y módulo.");
            }

            DiffieHellman diffieHellman = new DiffieHellman(base, modulo);
            diffieHellman.generarClavePublica();
            BigInteger clavePublicaCliente = diffieHellman.obtenerClavePublica();
            salida.println(clavePublicaCliente);
            System.out.println("Cliente " + id + ": Clave pública del cliente enviada al servidor con éxito.");

            diffieHellman.generarClaveCompartida(clavePublicaServidor);
            byte[] hash = diffieHellman.generarHash();
            System.out.println("Cliente " + id + ": Clave compartida generada con éxito.");

            HMAC hmac = new HMAC(hash);
            AES aes = new AES(hash);
            aes.generarVector();
            byte[] vector = aes.obtenerVector();
            String vectorBase64 = Base64.getEncoder().encodeToString(vector);
            salida.println(vectorBase64);
            System.out.println("Cliente " + id + ": Vector de inicialización enviado al servidor con éxito.");

            String serviciosBase64 = entrada.readLine();
            byte[] serviciosCifrados = Base64.getDecoder().decode(serviciosBase64);
            byte[] serviciosDescifrados = aes.descifrar(serviciosCifrados);
            ArrayList<Servicio> servicios = deserializarServicios(serviciosDescifrados);
            System.out.println("Cliente " + id + ": Servicios cifrados recibidos del servidor con éxito.");

            String firmaServiciosBase64 = entrada.readLine();
            byte[] firmaServicios = Base64.getDecoder().decode(firmaServiciosBase64);
            boolean verificacionServicios = hmac.verificarHash(serviciosDescifrados, firmaServicios);
            System.out.println("Cliente " + id + ": Firma de los servicios recibida del servidor con éxito.");

            if (verificacionServicios) {
                salida.println("OK");
                System.out.println("Cliente " + id + ": La verificación de la firma de los servicios ha sido exitosa.");
            } 
            else {
                salida.println("ERROR");
                throw new Exception("Cliente " + id + ": Error en la verificación de la firma de los servicios.");
            }
            
            int indiceAleatorio = random.nextInt(servicios.size() + 2);
            int servicio;
            
            if (indiceAleatorio < servicios.size()) { 
                Servicio servicioSeleccionado = servicios.get(indiceAleatorio);
                servicio = servicioSeleccionado.obtenerId();
            }
            else {
                servicio = indiceAleatorio + 1;
            }  

            byte[] servicioBytes = Integer.toString(servicio).getBytes();
            byte[] servicioCifrado = aes.cifrar(servicioBytes);
            String servicioCifradoBase64 = Base64.getEncoder().encodeToString(servicioCifrado);
            salida.println(servicioCifradoBase64);

            byte[] ipClienteBytes = ip.getBytes();
            byte[] ipClienteCifrada = aes.cifrar(ipClienteBytes);
            String ipClienteCifradaBase64 = Base64.getEncoder().encodeToString(ipClienteCifrada);
            salida.println(ipClienteCifradaBase64);

            System.out.println("Cliente " + id + ": Servicio seleccionado e IP del cliente cifrados enviados al servidor con éxito.");

            byte[] firmaServicio = hmac.generarHash(servicioBytes);
            String firmaServicioBase64 = Base64.getEncoder().encodeToString(firmaServicio);
            salida.println(firmaServicioBase64);

            byte[] firmaIpCliente = hmac.generarHash(ipClienteBytes);
            String firmaIpClienteBase64 = Base64.getEncoder().encodeToString(firmaIpCliente);
            salida.println(firmaIpClienteBase64);

            System.out.println("Cliente " + id + ": Firma del servicio seleccionado e IP del cliente enviadas al servidor con éxito.");

            String respuestaFirmaConsulta = entrada.readLine();

            if (respuestaFirmaConsulta.equals("ERROR")) {
                throw new Exception("Cliente " + id + ": Error en la verificación de la firma del servicio seleccionado e IP del cliente.");
            }

            String ipServidorBase64 = entrada.readLine();
            byte[] ipServidorCifrada = Base64.getDecoder().decode(ipServidorBase64);
            byte[] ipServidorDescifrada = aes.descifrar(ipServidorCifrada);

            String puertoServidorBase64 = entrada.readLine();
            byte[] puertoServidorCifrado = Base64.getDecoder().decode(puertoServidorBase64);
            byte[] puertoServidorDescifrado = aes.descifrar(puertoServidorCifrado);

            System.out.println("Cliente " + id + ": IP y puerto del servidor del servicio seleccionado cifrados recibidos del servidor con éxito.");

            String firmaIpServidorBase64 = entrada.readLine();
            byte[] firmaIpServidor = Base64.getDecoder().decode(firmaIpServidorBase64);
            boolean verificacionIpServidor = hmac.verificarHash(ipServidorDescifrada, firmaIpServidor);

            String firmaPuertoServidorBase64 = entrada.readLine();
            byte[] firmaPuertoServidor = Base64.getDecoder().decode(firmaPuertoServidorBase64);
            boolean verificacionPuertoServidor = hmac.verificarHash(puertoServidorDescifrado, firmaPuertoServidor);

            System.out.println("Cliente " + id + ": Firmas de la IP y puerto del servidor del servicio seleccionado recibidas del servidor con éxito.");

            if (verificacionIpServidor && verificacionPuertoServidor) {
                salida.println("OK");
                System.out.println("Cliente " + id + ": La verificación de las firmas de la IP y puerto del servidor del servicio seleccionado ha sido exitosa.");
            } 
            else {
                salida.println("ERROR");
                throw new Exception("Cliente " + id + ": Error en la verificación de las firmas de la IP y puerto del servidor del servicio seleccionado.");
            }
        }

        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }   
    
    public static ArrayList<Servicio> deserializarServicios(byte[] datos) throws Exception {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(datos);
        ObjectInputStream objectStream = new ObjectInputStream(byteStream);
        @SuppressWarnings("unchecked")
        ArrayList<Servicio> servicios = (ArrayList<Servicio>) objectStream.readObject();
        return servicios;
    }
}