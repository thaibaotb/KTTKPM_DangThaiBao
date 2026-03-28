package library.decorator;

public class BrailleVersionDecorator extends BorrowDecorator {
    public BrailleVersionDecorator(Borrowable borrowable) {
        super(borrowable);
    }

    @Override
    public String getDescription() {
        return super.getDescription() + " + Phien ban chu noi";
    }
}