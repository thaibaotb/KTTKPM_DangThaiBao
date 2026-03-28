package payment.decorator;

public class DiscountDecorator extends PaymentDecorator {
    public DiscountDecorator(PaymentComponent component) {
        super(component);
    }

    @Override
    public double getAmount() {
        return component.getAmount() - 50000;
    }
}