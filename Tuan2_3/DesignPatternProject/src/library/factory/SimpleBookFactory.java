package library.factory;

import library.core.AudioBook;
import library.core.Book;
import library.core.EBook;
import library.core.PaperBook;

public class SimpleBookFactory extends BookFactory {
    @Override
    public Book createBook(String type, String id, String title, String author, String category) {
        switch (type.toLowerCase()) {
            case "paper":
                return new PaperBook(id, title, author, category);
            case "ebook":
                return new EBook(id, title, author, category);
            case "audio":
                return new AudioBook(id, title, author, category);
            default:
                throw new IllegalArgumentException("Loai sach khong hop le");
        }
    }
}