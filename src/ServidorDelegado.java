import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.math.BigInteger;

public class ServidorDelegado extends Thread {

    private Socket socket;
    private int id;
    private int maximoSolicitudes;
    private ArrayList<Servicio> servicios;

    public ServidorDelegado(Socket socket, int id, int solicitudes, ArrayList<Servicio> servicios) {
        this.socket = socket;
        this.id = id;
        this.maximoSolicitudes = solicitudes;
        this.servicios = servicios;
    }

    @Override
    public void run() {
        try (
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);
        ) {
            for (int i = 0; i < maximoSolicitudes; i++) {
                ejecutarProtocolo(socket, salida, entrada);

                if (maximoSolicitudes > 1) {
                    System.out.println("Servidor delegado " + id + ": Consulta " + (i + 1) + " del cliente procesada.");
                } 
                else {
                    System.out.println("Servidor delegado " + id + ": Consulta del cliente procesada.");
                }
            }

            socket.close();
            System.out.println("Servidor delegado " + id + ": Conexión cerrada con el cliente.");
        } 
        
        catch (Exception e) {
            System.out.println("Error en el servidor delegado " + id + ": " + e.getMessage());
        }
    }

    public void ejecutarProtocolo(Socket socket, PrintWriter salida, BufferedReader entrada) {

        try {
            RSA rsa = new RSA();
            rsa.cargarClavePrivada();
            PrivateKey clavePrivadaRSA = rsa.obtenerClavePrivada();
            System.out.println("Servidor delegado " + id + ": Clave privada cargada con éxito.");

            String retoBase64 = entrada.readLine();
            byte[] reto = Base64.getDecoder().decode(retoBase64);
            byte[] firma = RSA.firmar(reto, clavePrivadaRSA);
            System.out.println("Servidor delegado " + id + ": Reto recibido del cliente con éxito.");

            String firmaBase64 = Base64.getEncoder().encodeToString(firma);
            salida.println(firmaBase64); 
            System.out.println("Servidor delegado " + id + ": Firma del reto enviada al cliente con éxito.");

            String respuestaFirmaReto = entrada.readLine();

            if (respuestaFirmaReto.equals("ERROR")) {
                throw new Exception("Servidor delegado " + id + ": Error en la verificación de la firma del reto.");
            } 

            DiffieHellman diffieHellman = new DiffieHellman();
            diffieHellman.generarClavePublica();
            BigInteger clavePublicaServidor = diffieHellman.obtenerClavePublica();
            BigInteger base = diffieHellman.obtenerBase();
            BigInteger modulo = diffieHellman.obtenerModulo();
            salida.println(clavePublicaServidor);
            salida.println(base);
            salida.println(modulo);
            System.out.println("Servidor delegado " + id + ": Clave pública del servidor, base y módulo enviados al cliente con éxito.");

            byte[] firmaClavePublicaServidor = RSA.firmar(clavePublicaServidor.toByteArray(), clavePrivadaRSA);
            String firmaClavePublicaServidorBase64 = Base64.getEncoder().encodeToString(firmaClavePublicaServidor);
            salida.println(firmaClavePublicaServidorBase64);
            
            byte[] firmaBase = RSA.firmar(base.toByteArray(), clavePrivadaRSA);
            String firmaBaseBase64 = Base64.getEncoder().encodeToString(firmaBase);
            salida.println(firmaBaseBase64);

            byte[] firmaModulo = RSA.firmar(modulo.toByteArray(), clavePrivadaRSA);
            String firmaModuloBase64 = Base64.getEncoder().encodeToString(firmaModulo);
            salida.println(firmaModuloBase64);

            System.out.println("Servidor delegado " + id + ": Firmas de la clave pública del servidor, base y módulo enviadas al cliente con éxito.");

            String respuestaFirmaDiffieHellman = entrada.readLine();

            if (respuestaFirmaDiffieHellman.equals("ERROR")) {
                throw new Exception("Servidor delegado " + id + ": Error en la verificación de las firmas de la clave pública del servidor, base y módulo.");
            }

            BigInteger clavePublicaCliente = new BigInteger(entrada.readLine());
            System.out.println("Servidor delegado " + id + ": Clave pública del cliente recibida del cliente con éxito.");

            diffieHellman.generarClaveCompartida(clavePublicaCliente);
            byte[] hash = diffieHellman.generarHash();
            System.out.println("Servidor delegado " + id + ": Clave compartida generada con éxito.");

            HMAC hmac = new HMAC(hash);
            AES aes = new AES(hash);
            String vectorBase64 = entrada.readLine();
            byte[] vector = Base64.getDecoder().decode(vectorBase64);
            aes.generarVector(vector);
            System.out.println("Servidor delegado " + id + ": Vector de inicialización recibido del cliente con éxito.");

            byte[] serviciosBytes = serializarServicios(servicios);
            byte[] serviciosCifrados = aes.cifrar(serviciosBytes);
            String serviciosCifradosBase64 = Base64.getEncoder().encodeToString(serviciosCifrados);
            salida.println(serviciosCifradosBase64);
            System.out.println("Servidor delegado " + id + ": Servicios cifrados enviados al cliente con éxito.");

            byte[] firmaServicios = hmac.generarHash(serviciosBytes);
            String firmaServiciosBase64 = Base64.getEncoder().encodeToString(firmaServicios);
            salida.println(firmaServiciosBase64);
            System.out.println("Servidor delegado " + id + ": Firma de los servicios enviada al cliente con éxito.");

            String respuestaFirmaServicios = entrada.readLine();

            if (respuestaFirmaServicios.equals("ERROR")) {
                throw new Exception("Servidor delegado " + id + ": Error en la verificación de la firma de los servicios.");
            }

            String servicioBase64 = entrada.readLine(); 
            byte[] servicioCifrado = Base64.getDecoder().decode(servicioBase64);
            byte[] servicioDescifrado = aes.descifrar(servicioCifrado);
            int servicio = Integer.parseInt(new String(servicioDescifrado));

            String ipClienteBase64 = entrada.readLine();
            byte[] ipClienteCifrada = Base64.getDecoder().decode(ipClienteBase64);
            byte[] ipClienteDescifrada = aes.descifrar(ipClienteCifrada);

            System.out.println("Servidor delegado " + id + ": Servicio seleccionado e IP del cliente cifrados recibidos del cliente con éxito.");

            String firmaServicioBase64 = entrada.readLine();
            byte[] firmaServicio = Base64.getDecoder().decode(firmaServicioBase64);
            boolean verificacionServicio = hmac.verificarHash(servicioDescifrado, firmaServicio);

            String firmaIpClienteBase64 = entrada.readLine();
            byte[] firmaIpCliente = Base64.getDecoder().decode(firmaIpClienteBase64);
            boolean verificacionIp = hmac.verificarHash(ipClienteDescifrada, firmaIpCliente);

            System.out.println("Servidor delegado " + id + ": Firmas del servicio seleccionado e IP del cliente recibidas del cliente con éxito.");

            if (verificacionServicio && verificacionIp) {
                salida.println("OK");
                System.out.println("Servidor delegado " + id + ": La verificación de las firmas del servicio seleccionado e IP del cliente ha sido exitosa.");
            } 
            else {
                salida.println("ERROR");
                throw new Exception("Servidor delegado " + id + ": Error en la verificación de las firmas del servicio seleccionado e IP del cliente.");
            }

            String ipServidor;
            String puertoServidor;

            if (servicio > servicios.size()) {
                ipServidor = "192.168.2." + servicio;
                puertoServidor = "500" + servicio;
            }
            else {
                ipServidor = "-1";
                puertoServidor = "-1";
            }

            byte[] ipServidorBytes = ipServidor.getBytes();
            byte[] ipServidorCifrado = aes.cifrar(ipServidorBytes);
            String ipServidorCifradoBase64 = Base64.getEncoder().encodeToString(ipServidorCifrado);
            salida.println(ipServidorCifradoBase64);

            byte[] puertoServidorBytes = puertoServidor.getBytes();
            byte[] puertoServidorCifrado = aes.cifrar(puertoServidorBytes);
            String puertoServidorCifradoBase64 = Base64.getEncoder().encodeToString(puertoServidorCifrado);
            salida.println(puertoServidorCifradoBase64);

            System.out.println("Servidor delegado " + id + ": IP y puerto del servidor del servicio seleccionado cifrados enviados al cliente con éxito.");

            byte[] firmaIpServidor = hmac.generarHash(ipServidorBytes);
            String firmaIpServidorBase64 = Base64.getEncoder().encodeToString(firmaIpServidor);
            salida.println(firmaIpServidorBase64);

            byte[] firmaPuertoServidor = hmac.generarHash(puertoServidorBytes);
            String firmaPuertoServidorBase64 = Base64.getEncoder().encodeToString(firmaPuertoServidor);
            salida.println(firmaPuertoServidorBase64);

            System.out.println("Servidor delegado " + id + ": Firmas de la IP y puerto del servidor del servicio seleccionado enviadas al cliente con éxito.");

            String respuestaServidorServicio = entrada.readLine();

            if (respuestaServidorServicio.equals("ERROR")) {
                throw new Exception("Servidor delegado " + id + ": Error en la verificación de las firmas de la IP y puerto del servidor del servicio seleccionado.");
            }
        }

        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }   

    public static byte[] serializarServicios(ArrayList<Servicio> servicios) throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);
        objectStream.writeObject(servicios);
        objectStream.flush();
        objectStream.close();
        return byteStream.toByteArray();
    }
}