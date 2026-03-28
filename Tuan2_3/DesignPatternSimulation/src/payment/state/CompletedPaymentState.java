package payment.state;

import payment.PaymentTransaction;

public class CompletedPaymentState implements PaymentState {
    @Override
    public void handle(PaymentTransaction transaction) {
        System.out.println("[" + transaction.getTransactionId() + "] Completed: Giao dich thanh cong.");
    }

    @Override
    public String getStateName() {
        return "Completed";
    }
}