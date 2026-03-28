package library.decorator;

public class ExtendBorrowDecorator extends BorrowDecorator {
    public ExtendBorrowDecorator(Borrowable borrowable) {
        super(borrowable);
    }

    @Override
    public String getDescription() {
        return super.getDescription() + " + Gia han thoi gian muon";
    }
}