package library.factory;

import library.core.Book;

public abstract class BookFactory {
    public abstract Book createBook(String type, String id, String title, String author, String category);
}