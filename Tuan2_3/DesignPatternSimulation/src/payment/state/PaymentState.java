package payment.state;

import payment.PaymentTransaction;

public interface PaymentState {
    void handle(PaymentTransaction transaction);
    String getStateName();
}