package tax.decorator;

public class LuxuryTaxDecorator extends TaxDecorator {
    public LuxuryTaxDecorator(PriceComponent component) {
        super(component);
    }

    @Override
    public double getPrice() {
        return component.getPrice() * 1.20;
    }
}