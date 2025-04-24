public class Servicio {
    
    private final String id;
    private final String nombre;

    public Servicio(String id, String nombre) {
        this.id = id;
        this.nombre = nombre;
    }

    public String getId() {
        return this.id;
    }

    public String getNombre() {
        return this.nombre;
    }
}