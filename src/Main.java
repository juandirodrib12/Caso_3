import java.security.PublicKey;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        try {
            Scanner scanner = new Scanner(System.in);
            boolean continuar = true;

            while (continuar) {
                System.out.println();
                System.out.println("Menu de opciones:");
                System.out.println("0. Salir");
                System.out.println("1. Ejecutar el programa con un servidor de consulta y un cliente iterativo.");
                System.out.println("2. Ejecutar el programa con servidores y clientes concurrentes.");
                System.out.println("3. Comparar el tiempo de respuesta con cifrado simétrico y asimétrico.");
                System.out.println();
                System.out.println("Seleccione una opción: ");

                int opcion = scanner.nextInt();

                if (opcion == 0) {
                    continuar = false;
                    System.out.println("Saliendo del programa...");
                }

                else if (opcion == 1) {
                    System.out.println();
                    RSA rsa = new RSA();
                    rsa.generarClaves();

                    Thread servidorPrincipal = new ServidorPrincipal(1, 32);
                    servidorPrincipal.start();
                    Thread.sleep(1000); 

                    Thread cliente = new Cliente(1,32);
                    cliente.start();
                    cliente.join();

                    servidorPrincipal.join();
                }

                else if (opcion == 2) {
                    System.out.println();
                    System.out.println("Numero de clientes y servidores:");
                    System.out.println("1. 4 clientes");
                    System.out.println("2. 16 clientes");
                    System.out.println("3. 32 clientes");
                    System.out.println("4. 64 clientes");
                    System.out.println();
                    System.out.println("Seleccione una opción: ");

                    int[] clientes = {4, 16, 32, 64};
                    int opcionClientes = scanner.nextInt();
                    int maximoClientes = clientes[opcionClientes - 1];

                    System.out.println();
                    RSA rsa = new RSA();
                    rsa.generarClaves();

                    Thread servidorPrincipal = new ServidorPrincipal(maximoClientes, 1);
                    servidorPrincipal.start();
                    Thread.sleep(1000);

                    ArrayList<Thread> clientesArray = new ArrayList<>();
                    for (int i = 0; i < maximoClientes; i++) {
                        Thread cliente = new Cliente(i + 1,1);
                        clientesArray.add(cliente);
                        cliente.start();
                    }

                    for (int i = 0; i < maximoClientes; i++) {
                        clientesArray.get(i).join();
                    }

                    servidorPrincipal.join();
                }

                else if (opcion == 3) {
                    System.out.println();
                    Random random = new Random();
                    byte[] dato = new byte[48];
                    random.nextBytes(dato);

                    RSA rsa = new RSA();
                    rsa.generarClaves(); 
                    rsa.cargarClavePublica();
                    PublicKey clavePublica = rsa.obtenerClavePublica();

                    double inicioRSA = System.nanoTime();
                    RSA.cifrar(dato, clavePublica);
                    double finRSA = System.nanoTime();
                    double tiempoRSA = (finRSA - inicioRSA)/1000000; 
                    tiempoRSA = Math.round(tiempoRSA * 100.0) / 100.0;
                    System.out.println("Tiempo de cifrado RSA: " + tiempoRSA + " ms");

                    DiffieHellman diffieHellmanServidor = new DiffieHellman();
                    diffieHellmanServidor.generarClavePublica();
                    BigInteger clavePublicaServidor = diffieHellmanServidor.obtenerClavePublica();
                    BigInteger modulo = diffieHellmanServidor.obtenerModulo();
                    BigInteger base = diffieHellmanServidor.obtenerBase();
                    DiffieHellman diffieHellmanCliente = new DiffieHellman(base, modulo);
                    diffieHellmanCliente.generarClaveCompartida(clavePublicaServidor);
                    byte[] hashCliente = diffieHellmanCliente.generarHash();

                    AES aes = new AES(hashCliente);
                    aes.generarVector();
                    
                    double inicioAES = System.nanoTime();
                    aes.cifrar(dato);
                    double finAES = System.nanoTime();
                    double tiempoAES = (finAES - inicioAES)/1000000;
                    tiempoAES = Math.round(tiempoAES * 100.0) / 100.0;
                    System.out.println("Tiempo de cifrado AES: " + tiempoAES + " ms");
                }

                else {
                    System.out.println();
                    System.out.println("Opción no válida. Intente de nuevo.");
                }
            }

            scanner.close();
        } 
        
        catch (Exception e) {
            System.out.println();
            System.out.println("Error ejecutando el programa: " + e.getMessage());
        }
    }
}