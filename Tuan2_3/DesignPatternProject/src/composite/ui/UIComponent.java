package composite.ui;

public abstract class UIComponent {
    protected String name;

    public UIComponent(String name) {
        this.name = name;
    }

    public void add(UIComponent component) {
        throw new UnsupportedOperationException("Khong ho tro add");
    }

    public void remove(UIComponent component) {
        throw new UnsupportedOperationException("Khong ho tro remove");
    }

    public abstract void render(String indent);
}