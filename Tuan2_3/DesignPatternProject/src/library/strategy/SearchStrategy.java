package library.strategy;

import java.util.List;

import library.core.Book;

public interface SearchStrategy {
    List<Book> search(List<Book> books, String keyword);
}