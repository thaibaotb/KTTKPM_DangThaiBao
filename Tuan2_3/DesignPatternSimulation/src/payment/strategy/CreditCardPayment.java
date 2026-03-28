package payment.strategy;

public class CreditCardPayment implements PaymentStrategy {
    @Override
    public void pay(double amount) {
        System.out.println("Thanh toan " + amount + " VND bang The tin dung.");
    }
}