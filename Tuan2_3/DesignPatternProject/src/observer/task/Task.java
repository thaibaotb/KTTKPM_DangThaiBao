package observer.task;

import java.util.ArrayList;
import java.util.List;

import observer.core.Observer;
import observer.core.Subject;

public class Task implements Subject {
    private String taskName;
    private String status;
    private List<Observer> observers = new ArrayList<>();

    public Task(String taskName, String status) {
        this.taskName = taskName;
        this.status = status;
    }

    public void setStatus(String status) {
        this.status = status;
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
        String message = "Task '" + taskName + "' da thay doi trang thai thanh: " + status;
        for (Observer observer : observers) {
            observer.update(message);
        }
    }
}