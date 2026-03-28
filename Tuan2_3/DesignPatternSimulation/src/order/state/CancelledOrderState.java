package order.state;

import order.Order;
import order.strategy.RefundStrategy;

public class CancelledOrderState implements OrderState {
    private RefundStrategy refundStrategy;

    public CancelledOrderState(RefundStrategy refundStrategy) {
        this.refundStrategy = refundStrategy;
    }

    @Override
    public void handle(Order order) {
        System.out.println("[" + order.getOrderId() + "] Huy: Huy don hang.");
        refundStrategy.refund(order.getAmount());
    }

    @Override
    public String getStateName() {
        return "Huy";
    }
}