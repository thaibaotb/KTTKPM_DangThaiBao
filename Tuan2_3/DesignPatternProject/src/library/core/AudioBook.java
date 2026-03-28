package library.core;

public class AudioBook extends Book {
    public AudioBook(String id, String title, String author, String category) {
        super(id, title, author, category);
    }

    @Override
    public String getType() {
        return "AudioBook";
    }
}