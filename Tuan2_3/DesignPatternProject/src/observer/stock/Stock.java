package observer.stock;

import java.util.ArrayList;
import java.util.List;

import observer.core.Observer;
import observer.core.Subject;

public class Stock implements Subject {
    private String symbol;
    private double price;
    private List<Observer> observers = new ArrayList<>();

    public Stock(String symbol, double price) {
        this.symbol = symbol;
        this.price = price;
    }

    public void setPrice(double price) {
        this.price = price;
        notifyObservers();
    }

    @Override
    public void registerObserver(Observer observer) {
        observers.add(observer);
    }

    @Override
    public void removeObserver(Observer observer) {
        observers.remove(observer);
    }

    @Override
    public void notifyObservers() {
        String message = "Co phieu " + symbol + " da thay doi gia thanh: " + price;
        for (Observer observer : observers) {
            observer.update(message);
        }
    }
}