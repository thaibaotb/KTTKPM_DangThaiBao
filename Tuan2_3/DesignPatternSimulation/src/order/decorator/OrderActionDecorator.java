package order.decorator;

public abstract class OrderActionDecorator implements OrderAction {
    protected OrderAction decoratedAction;

    public OrderActionDecorator(OrderAction decoratedAction) {
        this.decoratedAction = decoratedAction;
    }

    @Override
    public void execute() {
        decoratedAction.execute();
    }
}