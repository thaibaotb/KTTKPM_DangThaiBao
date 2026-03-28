package order.decorator;

import order.Order;

public class BasicOrderAction implements OrderAction {
    private Order order;

    public BasicOrderAction(Order order) {
        this.order = order;
    }

    @Override
    public void execute() {
        System.out.println("Thuc hien hanh dong bo sung cho don hang " + order.getOrderId() + ".");
    }
}