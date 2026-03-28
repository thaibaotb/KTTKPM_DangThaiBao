package composite.ui;

public class Dialog extends UIComponent {
    public Dialog(String name) {
        super(name);
    }

    @Override
    public void render(String indent) {
        System.out.println(indent + "[Dialog] " + name);
    }
}