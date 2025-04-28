import java.io.Serializable;

public class Servicio implements Serializable {
    
    private final int id;
    private final String nombre;

    public Servicio(int id, String nombre) {
        this.id = id;
        this.nombre = nombre;
    }

    public int obtenerId() {
        return this.id;
    }

    public String obtenerNombre() {
        return this.nombre;
    }
}