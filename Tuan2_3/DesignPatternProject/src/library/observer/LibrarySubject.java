package library.observer;

public interface LibrarySubject {
    void registerObserver(LibraryObserver observer);
    void removeObserver(LibraryObserver observer);
    void notifyObservers(String message);
}