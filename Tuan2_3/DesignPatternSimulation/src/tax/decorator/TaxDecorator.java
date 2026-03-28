package tax.decorator;

public abstract class TaxDecorator implements PriceComponent {
    protected PriceComponent component;

    public TaxDecorator(PriceComponent component) {
        this.component = component;
    }
}