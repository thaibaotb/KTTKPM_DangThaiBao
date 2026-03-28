package order.state;

import order.Order;

public class DeliveredOrderState implements OrderState {
    @Override
    public void handle(Order order) {
        System.out.println("[" + order.getOrderId() + "] Da giao: Cap nhat trang thai don hang la da giao.");
    }

    @Override
    public String getStateName() {
        return "Da giao";
    }
}