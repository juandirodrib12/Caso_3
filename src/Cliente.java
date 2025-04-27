import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Cliente extends Thread {

    private int id;
    private int maximoSolicitudes;

    public Cliente(int id, int solicitudes) {
        this.id = id;
        this.maximoSolicitudes = solicitudes;
    }

    @Override
    public void run() {
        try (
            Socket socket = new Socket("localhost", 5000);
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        ) {
            for (int i = 0; i < maximoSolicitudes; i++) {
                String mensaje = "Hola, soy el cliente " + id;
                salida.println(mensaje);

                String respuesta = entrada.readLine();
                System.out.println("Cliente " + id + ": " + respuesta);
            }
        } 

        catch (Exception e) {
            System.out.println("Error en el cliente " + id + ": " + e.getMessage());
        }
    }
}