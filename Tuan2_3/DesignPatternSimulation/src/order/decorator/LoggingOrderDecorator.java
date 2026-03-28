package order.decorator;

public class LoggingOrderDecorator extends OrderActionDecorator {
    public LoggingOrderDecorator(OrderAction decoratedAction) {
        super(decoratedAction);
    }

    @Override
    public void execute() {
        super.execute();
        System.out.println("-> Ghi log xu ly don hang.");
    }
}