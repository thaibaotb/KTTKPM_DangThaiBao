package payment.strategy;

public class PayPalPayment implements PaymentStrategy {
    @Override
    public void pay(double amount) {
        System.out.println("Thanh toan " + amount + " VND bang PayPal.");
    }
}