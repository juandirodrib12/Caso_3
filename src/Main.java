import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        try {

            Scanner scanner = new Scanner(System.in);
            System.out.println("Escriba el número correspondiente a la opción: ");
            System.out.println("1. Un servidor de consulta y un cliente iterativo.");
            System.out.println("2. Servidor y clientes concurrentes.");
            System.out.println("3. Comparar el tiempo de respuesta con cifrado simétrico y con cifrado asimétrico. "); 
            
            int opcion = scanner.nextInt();
            if (opcion == 1) {
                // Lanzar el servidor de consulta y el cliente iterativo para hacer 32 consultas
                Thread servidor = new ServidorPrincipal();
                servidor.start();

                Cliente cliente = new Cliente(1, 1); 
                cliente.ejecutar();

                servidor.join();
        
                System.out.println("Prueba finalizada: todos los clientes fueron atendidos y el servidor ha cerrado.");

            } else if (opcion == 2) {
                System.out.println("Escriba la cantidad de servidores delegados concurrentes (4, 16, 32 y 64): ");
                int nueva = scanner.nextInt();
                List<Integer> validos = Arrays.asList(4, 16, 32, 64);
                if (!validos.contains(nueva)) {
                    System.out.println("Número de servidores no válido. Por favor, elija entre 4, 16, 32 o 64.");
                }else {
                    Thread servidor = new ServidorPrincipal();
                    servidor.start();
        
                    // Esperar un momento para asegurar que el servidor esté corriendo
                    Thread.sleep(1000);
        
                    // Lanzar 8 clientes en hilos y guardarlos para join
                    Thread[] clientes = new Thread[nueva];
                    for (int i = 0; i < nueva; i++) {
                        final int idCliente = i + 1;
                        clientes[i] = new Thread(() -> {
                            Cliente clienteHilo = new Cliente(idCliente, 1);
                            clienteHilo.ejecutar();
                        });
                        clientes[i].start();
                    }
        
                    // Esperar a que todos los clientes terminen
                    for (Thread cliente : clientes) {
                        cliente.join();
                    }
        
                    // Esperar a que el servidor principal termine
                    servidor.join();
        
                    System.out.println("Prueba finalizada: todos los clientes fueron atendidos y el servidor ha cerrado.");
        
                }
            } else if (opcion == 3) {
                int[] cantidadesClientes = {1, 4, 16, 32, 64};
            
                for (int cantidad : cantidadesClientes) {
                    System.out.println("Probando con " + cantidad + " clientes concurrentes.");
            
                    long totalTiempoAES = 0;
                    long totalTiempoRSA = 0;
            
                    Thread[] clientes = new Thread[cantidad];
                    long[] tiemposAES = new long[cantidad];
                    long[] tiemposRSA = new long[cantidad];
            
                    for (int i = 0; i < cantidad; i++) {
                        final int id = i;
                        clientes[i] = new Thread(() -> {
                            try {
                                String mensaje = "respuesta del servidor: vuelos disponibles";
            
                                byte[] hashFalso = new byte[64];
                                SecureRandom random = new SecureRandom();
                                random.nextBytes(hashFalso);
            
                                AES aes = new AES(hashFalso);
                                aes.generarVector();
            
                                long inicioAES = System.nanoTime();
                                byte[] cifradoAES = aes.cifrar(mensaje.getBytes());
                                long finAES = System.nanoTime();
                                tiemposAES[id] = finAES - inicioAES;
            
                                RSA rsa = new RSA();
                                rsa.cargarClavePublica();
            
                                long inicioRSA = System.nanoTime();
                                byte[] cifradoRSA = RSA.cifrar(mensaje.getBytes(), rsa.obtenerClavePublica());
                                long finRSA = System.nanoTime();
                                tiemposRSA[id] = finRSA - inicioRSA;
            
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        });
                        clientes[i].start();
                    }
            
                    // Esperar que todos terminen
                    for (Thread cliente : clientes) {
                        try {
                            cliente.join();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
            
                    // Sumar tiempos
                    for (int i = 0; i < cantidad; i++) {
                        totalTiempoAES += tiemposAES[i];
                        totalTiempoRSA += tiemposRSA[i];
                    }
            
                    // Calcular promedios
                    long promedioAES = totalTiempoAES / cantidad;
                    long promedioRSA = totalTiempoRSA / cantidad;
            
                    System.out.println("Promedio tiempo AES para " + cantidad + " clientes: " + promedioAES + " ns");
                    System.out.println("Promedio tiempo RSA para " + cantidad + " clientes: " + promedioRSA + " ns");
                }
            } else if (opcion == 0) {
                System.out.println("Saliendo del programa.");
                return;
            }
            else {
                System.out.println("Opción no válida. Por favor, elija una opción válida.");
            }
            scanner.close();
        } catch (Exception e) {
            System.out.println("Error al iniciar la prueba: " + e.getMessage());
        }
    }
}
