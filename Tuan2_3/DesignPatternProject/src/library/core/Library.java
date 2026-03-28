package library.core;

import java.util.ArrayList;
import java.util.List;

import library.observer.LibraryObserver;
import library.observer.LibrarySubject;

public class Library implements LibrarySubject {
    private static Library instance;
    private List<Book> books = new ArrayList<>();
    private List<LibraryObserver> observers = new ArrayList<>();

    private Library() {
    }

    public static Library getInstance() {
        if (instance == null) {
            instance = new Library();
        }
        return instance;
    }

    public void addBook(Book book) {
        books.add(book);
        notifyObservers("Thu vien vua them sach moi: " + book.getTitle());
    }

    public void removeBook(Book book) {
        books.remove(book);
    }

    public List<Book> getBooks() {
        return books;
    }

    public void notifyOverdueBook(Book book) {
        notifyObservers("Sach qua han muon: " + book.getTitle());
    }

    @Override
    public void registerObserver(LibraryObserver observer) {
        observers.add(observer);
    }

    @Override
    public void removeObserver(LibraryObserver observer) {
        observers.remove(observer);
    }

    @Override
    public void notifyObservers(String message) {
        for (LibraryObserver observer : observers) {
            observer.update(message);
        }
    }
}