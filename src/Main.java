public class Main {

    public static void main(String[] args) {
        try {
            // Lanzar el servidor principal en un hilo aparte
            Thread servidor = new ServidorPrincipal();
            servidor.start();

            // Esperar un momento para asegurar que el servidor esté corriendo
            Thread.sleep(1000);

            // Lanzar 8 clientes en hilos y guardarlos para join
            Thread[] clientes = new Thread[8];
            for (int i = 0; i < 1; i++) {
                final int idCliente = i + 1;
                clientes[i] = new Thread(() -> {
                    Cliente clienteHilo = new Cliente(idCliente);
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

        } catch (Exception e) {
            System.out.println("Error al iniciar la prueba: " + e.getMessage());
        }
    }
}
