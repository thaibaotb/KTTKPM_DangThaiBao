package library.observer;

public class Subscriber implements LibraryObserver {
    private String name;

    public Subscriber(String name) {
        this.name = name;
    }

    @Override
    public void update(String message) {
        System.out.println("Nguoi dang ky " + name + " nhan thong bao: " + message);
    }
}