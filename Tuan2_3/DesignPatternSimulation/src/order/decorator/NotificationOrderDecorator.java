package order.decorator;

public class NotificationOrderDecorator extends OrderActionDecorator {
    public NotificationOrderDecorator(OrderAction decoratedAction) {
        super(decoratedAction);
    }

    @Override
    public void execute() {
        super.execute();
        System.out.println("-> Gui thong bao cho khach hang.");
    }
}