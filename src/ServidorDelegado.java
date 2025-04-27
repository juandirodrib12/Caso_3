import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ServidorDelegado extends Thread {

    private Socket socket;
    private int id;
    private int maximoSolicitudes;

    public ServidorDelegado(Socket socket, int id, int solicitudes) {
        this.socket = socket;
        this.id = id;
        this.maximoSolicitudes = solicitudes;
    }

    @Override
    public void run() {
        try (
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);
        ) {
            for (int i = 0; i < maximoSolicitudes; i++) {
                String mensaje = entrada.readLine();
                System.out.println("Delegado " + id + " recibió: " + mensaje);
                salida.println("El cliente fue atendido por el delegado " + id);
            }
            socket.close();
        } 
        
        catch (Exception e) {
            System.out.println("Error en el delegado " + id + ": " + e.getMessage());
        }
    }
}
