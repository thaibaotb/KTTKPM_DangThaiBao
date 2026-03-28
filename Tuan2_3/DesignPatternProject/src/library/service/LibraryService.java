package library.service;

import java.util.List;

import library.core.Book;
import library.core.Library;
import library.decorator.BasicBorrow;
import library.decorator.Borrowable;
import library.factory.BookFactory;
import library.strategy.SearchContext;

public class LibraryService {
    private Library library;
    private BookFactory factory;

    public LibraryService(Library library, BookFactory factory) {
        this.library = library;
        this.factory = factory;
    }

    public Book addBook(String type, String id, String title, String author, String category) {
        Book book = factory.createBook(type, id, title, author, category);
        library.addBook(book);
        return book;
    }

    public void showAllBooks() {
        System.out.println("Danh sach sach trong thu vien:");
        for (Book book : library.getBooks()) {
            System.out.println(book);
        }
    }

    public List<Book> searchBooks(SearchContext context, String keyword) {
        return context.search(library.getBooks(), keyword);
    }

    public Borrowable borrowBook(Book book) {
        return new BasicBorrow(book);
    }

    public void returnBook(Book book) {
        System.out.println("Tra sach: " + book.getTitle());
    }

    public void markOverdue(Book book) {
        library.notifyOverdueBook(book);
    }
}