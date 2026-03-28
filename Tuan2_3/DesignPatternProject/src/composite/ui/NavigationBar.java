package composite.ui;

public class NavigationBar extends UIComponent {
    public NavigationBar(String name) {
        super(name);
    }

    @Override
    public void render(String indent) {
        System.out.println(indent + "[NavigationBar] " + name);
    }
}