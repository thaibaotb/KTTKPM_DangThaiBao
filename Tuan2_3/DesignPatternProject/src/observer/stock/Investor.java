package observer.stock;

import observer.core.Observer;

public class Investor implements Observer {
    private String name;

    public Investor(String name) {
        this.name = name;
    }

    @Override
    public void update(String message) {
        System.out.println("Nha dau tu " + name + " nhan thong bao: " + message);
    }
}