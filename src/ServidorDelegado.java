import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

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
            String mensaje = entrada.readLine();
            System.out.println("Delegado " + idDelegado + " recibió: " + mensaje);
            salida.println("El cliente fue atendido por el delegado " + idDelegado);
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
