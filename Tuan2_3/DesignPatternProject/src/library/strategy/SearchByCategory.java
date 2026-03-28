package library.strategy;

import java.util.ArrayList;
import java.util.List;

import library.core.Book;

public class SearchByCategory implements SearchStrategy {
    @Override
    public List<Book> search(List<Book> books, String keyword) {
        List<Book> result = new ArrayList<>();
        for (Book book : books) {
            if (book.getCategory().toLowerCase().contains(keyword.toLowerCase())) {
                result.add(book);
            }
        }
        return result;
    }
}