package payment;

import payment.state.PaymentState;
import payment.state.PendingPaymentState;

public class PaymentTransaction {
    private String transactionId;
    private PaymentState state;

    public PaymentTransaction(String transactionId) {
        this.transactionId = transactionId;
        this.state = new PendingPaymentState();
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setState(PaymentState state) {
        this.state = state;
    }

    public PaymentState getState() {
        return state;
    }

    public String getStateName() {
        return state.getStateName();
    }

    public void process() {
        state.handle(this);
    }
}