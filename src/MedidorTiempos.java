import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class MedidorTiempos {

    private ArrayList<Double> tiemposFirmar;
    private ArrayList<Double> tiemposCifrar;
    private ArrayList<Double> tiemposVerificar;

    public MedidorTiempos() {
        tiemposFirmar = new ArrayList<>();
        tiemposCifrar = new ArrayList<>();
        tiemposVerificar = new ArrayList<>();
    }

    public void agregarTiempoFirmar(double tiempo) {
        tiemposFirmar.add(tiempo);
    }

    public void agregarTiempoCifrar(double tiempo) {
        tiemposCifrar.add(tiempo);
    }

    public void agregarTiempoVerificar(double tiempo) {
        tiemposVerificar.add(tiempo);
    }

    public double promedioFirmar() {
        return calcularPromedio(tiemposFirmar);
    }

    public double promedioCifrar() {
        return calcularPromedio(tiemposCifrar);
    }

    public double promedioVerificar() {
        return calcularPromedio(tiemposVerificar);
    }

    private double calcularPromedio(ArrayList<Double> lista) {
        if (lista.isEmpty()) return 0;

        double suma = 0.0;
        for (double tiempo : lista) {
            suma += tiempo;
        }
        double promedio = suma / lista.size();

        return Math.round(promedio * 100.0) / 100.0;
    }

    public void exportarCSV(String nombreArchivo) {
        try (FileWriter writer = new FileWriter(nombreArchivo)) {
            writer.append("Operación, Promedio (ms)\n");
            writer.append("Firmar," + promedioFirmar() + "\n");
            writer.append("Cifrar," + promedioCifrar() + "\n");
            writer.append("Verificar," + promedioVerificar() + "\n");
        } 
        catch (IOException e) {
            System.out.println("Error al exportar CSV: " + e.getMessage());
        }
    }
}