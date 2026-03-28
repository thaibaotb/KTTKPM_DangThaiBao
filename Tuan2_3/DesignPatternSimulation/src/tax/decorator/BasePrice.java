package tax.decorator;

public class BasePrice implements PriceComponent {
    private double price;

    public BasePrice(double price) {
        this.price = price;
    }

    @Override
    public double getPrice() {
        return price;
    }
}