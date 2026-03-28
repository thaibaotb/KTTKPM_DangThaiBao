package order.state;

import order.Order;

public class NewOrderState implements OrderState {
    @Override
    public void handle(Order order) {
        System.out.println("[" + order.getOrderId() + "] Moi tao: Kiem tra thong tin don hang.");
        order.setState(new ProcessingOrderState());
    }

    @Override
    public String getStateName() {
        return "Moi tao";
    }
}