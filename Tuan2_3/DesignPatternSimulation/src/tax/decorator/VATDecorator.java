package tax.decorator;

public class VATDecorator extends TaxDecorator {
    public VATDecorator(PriceComponent component) {
        super(component);
    }

    @Override
    public double getPrice() {
        return component.getPrice() * 1.10;
    }
}