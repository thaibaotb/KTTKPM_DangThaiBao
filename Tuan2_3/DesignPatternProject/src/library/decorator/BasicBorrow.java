package library.decorator;

import library.core.Book;

public class BasicBorrow implements Borrowable {
    private Book book;

    public BasicBorrow(Book book) {
        this.book = book;
    }

    @Override
    public String getDescription() {
        return "Muon sach: " + book.getTitle();
    }
}