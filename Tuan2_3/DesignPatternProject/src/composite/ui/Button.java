package composite.ui;

public class Button extends UIComponent {
    public Button(String name) {
        super(name);
    }

    @Override
    public void render(String indent) {
        System.out.println(indent + "[Button] " + name);
    }
}