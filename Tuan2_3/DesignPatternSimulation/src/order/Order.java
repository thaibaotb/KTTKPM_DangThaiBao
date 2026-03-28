package order;

import order.state.NewOrderState;
import order.state.OrderState;

public class Order {
    private String orderId;
    private double amount;
    private OrderState state;

    public Order(String orderId, double amount) {
        this.orderId = orderId;
        this.amount = amount;
        this.state = new NewOrderState();
    }

    public String getOrderId() {
        return orderId;
    }

    public double getAmount() {
        return amount;
    }

    public void setState(OrderState state) {
        this.state = state;
    }

    public OrderState getState() {
        return state;
    }

    public String getStateName() {
        return state.getStateName();
    }

    public void process() {
        state.handle(this);
    }
}