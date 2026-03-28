package order.state;

import order.Order;

public interface OrderState {
    void handle(Order order);
    String getStateName();
}