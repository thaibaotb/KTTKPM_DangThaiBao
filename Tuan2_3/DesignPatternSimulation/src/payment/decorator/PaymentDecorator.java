package payment.decorator;

public abstract class PaymentDecorator implements PaymentComponent {
    protected PaymentComponent component;

    public PaymentDecorator(PaymentComponent component) {
        this.component = component;
    }
}