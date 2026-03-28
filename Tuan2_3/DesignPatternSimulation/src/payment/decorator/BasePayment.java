package payment.decorator;

public class BasePayment implements PaymentComponent {
    private double amount;

    public BasePayment(double amount) {
        this.amount = amount;
    }

    @Override
    public double getAmount() {
        return amount;
    }
}