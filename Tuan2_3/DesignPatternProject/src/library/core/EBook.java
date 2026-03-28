package library.core;

public class EBook extends Book {
    public EBook(String id, String title, String author, String category) {
        super(id, title, author, category);
    }

    @Override
    public String getType() {
        return "EBook";
    }
}