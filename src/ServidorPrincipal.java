import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class ServidorPrincipal extends Thread {

    private static final int PUERTO = 5000;
    private ServerSocket servidor;
    private List<Thread> delegados;
    private ArrayList<Servicio> servicios;
    private int maximoConexiones;
    private int maximoSolicitudes;

    public ServidorPrincipal(int conexiones, int solicitudes) throws Exception {
        this.servidor = new ServerSocket(PUERTO);
        this.maximoConexiones = conexiones;
        this.delegados = new ArrayList<>();
        this.maximoSolicitudes = solicitudes;
        this.servicios = generarServicios();
    }

    public ArrayList<Servicio> generarServicios() {
        ArrayList<Servicio> servicios = new ArrayList<>();
        servicios.add(new Servicio(1, "Estado Vuelo"));
        servicios.add(new Servicio(2, "Disponibilidad Vuelos"));
        servicios.add(new Servicio(3, "Costo Vuelo"));
        return servicios;
    }

    public void run() {

        try {
            int conexiones = 0;
            System.out.println("Servidor principal: Servidor iniciado en el puerto " + PUERTO);
            System.out.println("Servidor principal: Esperando conexiones de clientes...");

            while (conexiones < maximoConexiones) {
                Socket socketCliente = servidor.accept();
                int idDelegado = conexiones + 1;
                Thread delegado = new ServidorDelegado(socketCliente, idDelegado, maximoSolicitudes, servicios);
                delegados.add(delegado);
                delegado.start();
                conexiones++;
            }

            for (Thread delegado : delegados) {
                delegado.join();
            }

            servidor.close();
            System.out.println("Servidor principal: Todas las conexiones han sido atendidas.");
            System.out.println("Servidor principal: Servidor cerrado.");
        } 
        
        catch (Exception e) {
            System.out.println("Error en el servidor principal: " + e.getMessage());
        }
    }
}