package order.strategy;

public class BankRefundStrategy implements RefundStrategy {
    @Override
    public void refund(double amount) {
        System.out.println("Hoan tien " + amount + " VND qua tai khoan ngan hang.");
    }
}