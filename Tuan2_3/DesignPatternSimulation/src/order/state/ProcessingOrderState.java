package order.state;

import order.Order;

public class ProcessingOrderState implements OrderState {
    @Override
    public void handle(Order order) {
        System.out.println("[" + order.getOrderId() + "] Dang xu ly: Dong goi va van chuyen.");
        order.setState(new DeliveredOrderState());
    }

    @Override
    public String getStateName() {
        return "Dang xu ly";
    }
}