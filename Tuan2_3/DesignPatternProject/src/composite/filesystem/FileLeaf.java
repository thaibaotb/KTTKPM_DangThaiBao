package composite.filesystem;

public class FileLeaf extends FileSystemComponent {
    private int size;

    public FileLeaf(String name, int size) {
        super(name);
        this.size = size;
    }

    @Override
    public void display(String indent) {
        System.out.println(indent + "- File: " + name + " (" + size + "KB)");
    }
}