package composite.filesystem;

import java.util.ArrayList;
import java.util.List;

public class FolderComposite extends FileSystemComponent {
    private List<FileSystemComponent> children = new ArrayList<>();

    public FolderComposite(String name) {
        super(name);
    }

    @Override
    public void add(FileSystemComponent component) {
        children.add(component);
    }

    @Override
    public void remove(FileSystemComponent component) {
        children.remove(component);
    }

    @Override
    public void display(String indent) {
        System.out.println(indent + "+ Folder: " + name);
        for (FileSystemComponent child : children) {
            child.display(indent + "   ");
        }
    }
}