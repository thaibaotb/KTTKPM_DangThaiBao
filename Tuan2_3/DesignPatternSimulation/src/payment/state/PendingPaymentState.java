package payment.state;

import payment.PaymentTransaction;

public class PendingPaymentState implements PaymentState {
    @Override
    public void handle(PaymentTransaction transaction) {
        System.out.println("[" + transaction.getTransactionId() + "] Pending: Dang xu ly giao dich.");
        transaction.setState(new CompletedPaymentState());
    }

    @Override
    public String getStateName() {
        return "Pending";
    }
}