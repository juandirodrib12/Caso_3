import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class ServidorPrincipal extends Thread {

    private static final int PUERTO = 5000;
    private ServerSocket servidor;
    private List<Thread> delegados;
    private int maximoConexiones;
    private int maximoSolicitudes;

    public ServidorPrincipal(int conexiones, int solicitudes) throws IOException {
        this.servidor = new ServerSocket(PUERTO);
        this.maximoConexiones = conexiones;
        this.delegados = new ArrayList<>();
        this.maximoSolicitudes = solicitudes;
    }

    public void run() {

        try {
            int conexiones = 0;

            while (conexiones < maximoConexiones) {
                Socket socketCliente = servidor.accept();
                int idDelegado = conexiones + 1;
                Thread delegado = new ServidorDelegado(socketCliente, idDelegado, maximoSolicitudes);
                delegados.add(delegado);
                delegado.start();
                conexiones++;
            }

            for (Thread delegado : delegados) {
                delegado.join();
            }

            servidor.close();
        } 
        
        catch (Exception e) {
            System.out.println("Error ejecutando el programa: " + e.getMessage());
        }
    }
}