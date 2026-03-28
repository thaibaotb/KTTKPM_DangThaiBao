package tax.decorator;

public class ConsumptionTaxDecorator extends TaxDecorator {
    public ConsumptionTaxDecorator(PriceComponent component) {
        super(component);
    }

    @Override
    public double getPrice() {
        return component.getPrice() * 1.05;
    }
}