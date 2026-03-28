package library.core;

public class PaperBook extends Book {
    public PaperBook(String id, String title, String author, String category) {
        super(id, title, author, category);
    }

    @Override
    public String getType() {
        return "PaperBook";
    }
}