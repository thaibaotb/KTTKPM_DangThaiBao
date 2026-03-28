package payment.state;

import payment.PaymentTransaction;

public class FailedPaymentState implements PaymentState {
    @Override
    public void handle(PaymentTransaction transaction) {
        System.out.println("[" + transaction.getTransactionId() + "] Failed: Giao dich that bai.");
    }

    @Override
    public String getStateName() {
        return "Failed";
    }
}