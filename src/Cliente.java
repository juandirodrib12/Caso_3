import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

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
            String mensaje = "Hola, soy el cliente " + idCliente;
            salida.println(mensaje);

            String respuesta = entrada.readLine();
            System.out.println("Cliente " + idCliente + ": " + respuesta);
        } catch (Exception e) {
            System.out.println("Error en el cliente " + idCliente + ": " + e.getMessage());
        }
    }
}
