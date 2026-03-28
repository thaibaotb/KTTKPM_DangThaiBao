package composite.filesystem;

public abstract class FileSystemComponent {
    protected String name;

    public FileSystemComponent(String name) {
        this.name = name;
    }

    public void add(FileSystemComponent component) {
        throw new UnsupportedOperationException("Khong ho tro add");
    }

    public void remove(FileSystemComponent component) {
        throw new UnsupportedOperationException("Khong ho tro remove");
    }

    public abstract void display(String indent);
}