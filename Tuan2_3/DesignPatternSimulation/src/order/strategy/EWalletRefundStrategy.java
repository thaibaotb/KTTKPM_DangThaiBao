package order.strategy;

public class EWalletRefundStrategy implements RefundStrategy {
    @Override
    public void refund(double amount) {
        System.out.println("Hoan tien " + amount + " VND qua vi dien tu.");
    }
}