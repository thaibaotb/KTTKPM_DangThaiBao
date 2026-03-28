package order;

public class OrderService {
    public void printOrderInfo(Order order) {
        System.out.println("Don hang: " + order.getOrderId() + ", so tien: " + order.getAmount());
    }
}