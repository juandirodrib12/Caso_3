import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class ServidorPrincipal extends Thread {

    private static final int PUERTO_ESCUCHA = 5000;
    private static final int MAX_CONEXIONES = 4;

    private ServerSocket servidor;
    private List<Thread> delegados;

    public ServidorPrincipal() throws IOException {
        servidor = new ServerSocket(PUERTO_ESCUCHA);
        delegados = new ArrayList<>();
        System.out.println("Servidor principal iniciado en el puerto " + PUERTO_ESCUCHA);
    }

    public void run() {
        try {
            int conexiones = 0;
            while (conexiones < MAX_CONEXIONES) {
                Socket socketCliente = servidor.accept();
                int idDelegado = conexiones + 1;
                System.out.println("Cliente aceptado. Creando delegado " + idDelegado);

                Thread delegado = new Thread(new ServidorDelegado(socketCliente, idDelegado));
                delegados.add(delegado);
                delegado.start();
                conexiones++;
            }

            for (Thread delegado : delegados) {
                delegado.join();
            }
            System.out.println("Todos los delegados han finalizado. Cerrando servidor.");
        } catch (IOException | InterruptedException e) {
            System.out.println("Error en el servidor: " + e.getMessage());
        } finally {
            try {
                servidor.close();
            } catch (IOException e) {
                System.out.println("Error al cerrar el servidor: " + e.getMessage());
            }
        }
    }
}