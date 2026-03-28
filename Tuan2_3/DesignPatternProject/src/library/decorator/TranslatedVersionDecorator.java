package library.decorator;

public class TranslatedVersionDecorator extends BorrowDecorator {
    public TranslatedVersionDecorator(Borrowable borrowable) {
        super(borrowable);
    }

    @Override
    public String getDescription() {
        return super.getDescription() + " + Ban dich";
    }
}