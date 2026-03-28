package composite.ui;

import java.util.ArrayList;
import java.util.List;

public class UIGroup extends UIComponent {
    private List<UIComponent> children = new ArrayList<>();

    public UIGroup(String name) {
        super(name);
    }

    @Override
    public void add(UIComponent component) {
        children.add(component);
    }

    @Override
    public void remove(UIComponent component) {
        children.remove(component);
    }

    @Override
    public void render(String indent) {
        System.out.println(indent + "[UIGroup] " + name);
        for (UIComponent child : children) {
            child.render(indent + "   ");
        }
    }
}