import order.Order;
import order.OrderService;
import order.decorator.BasicOrderAction;
import order.decorator.LoggingOrderDecorator;
import order.decorator.NotificationOrderDecorator;
import order.decorator.OrderAction;
import order.state.CancelledOrderState;
import order.strategy.BankRefundStrategy;

import tax.Product;
import tax.TaxService;
import tax.decorator.BasePrice;
import tax.decorator.ConsumptionTaxDecorator;
import tax.decorator.LuxuryTaxDecorator;
import tax.decorator.PriceComponent;
import tax.decorator.VATDecorator;
import tax.state.ImportedTaxState;
import tax.state.LuxuryTaxState;
import tax.strategy.ConsumptionTaxStrategy;
import tax.strategy.LuxuryTaxStrategy;
import tax.strategy.VATTaxStrategy;

import payment.PaymentService;
import payment.PaymentTransaction;
import payment.decorator.BasePayment;
import payment.decorator.DiscountDecorator;
import payment.decorator.PaymentComponent;
import payment.decorator.ProcessingFeeDecorator;
import payment.strategy.CreditCardPayment;
import payment.strategy.PayPalPayment;

public class Main {
    public static void main(String[] args) {
        System.out.println("========== YEU CAU 1: QUAN LY DON HANG ==========");
        simulateOrderSystem();

        System.out.println("\n========== YEU CAU 2: TINH TOAN THUE SAN PHAM ==========");
        simulateTaxSystem();

        System.out.println("\n========== YEU CAU 3: HE THONG THANH TOAN ==========");
        simulatePaymentSystem();

        System.out.println("\n========== KET LUAN ==========");
        printConclusion();
    }

    private static void simulateOrderSystem() {
        Order order = new Order("ORD001", 500000);

        System.out.println("Trang thai hien tai: " + order.getStateName());
        order.process();

        System.out.println("Trang thai hien tai: " + order.getStateName());
        order.process();

        System.out.println("Trang thai hien tai: " + order.getStateName());
        order.process();

        System.out.println("\nDecorator cho don hang:");
        OrderAction action = new NotificationOrderDecorator(
                new LoggingOrderDecorator(
                        new BasicOrderAction(order)
                )
        );
        action.execute();

        System.out.println("\nHuy don voi Strategy:");
        order.setState(new CancelledOrderState(new BankRefundStrategy()));
        System.out.println("Trang thai hien tai: " + order.getStateName());
        order.process();
    }

    private static void simulateTaxSystem() {
        Product product = new Product("Laptop", 20000000);

        product.setTaxState(new ImportedTaxState());
        System.out.println("Trang thai thue san pham: " + product.getTaxStateName());
        product.showStateDescription();

        TaxService service = new TaxService();

        service.setTaxStrategy(new VATTaxStrategy());
        System.out.println("VAT = " + service.calculateTax(product));

        service.setTaxStrategy(new ConsumptionTaxStrategy());
        System.out.println("Thue tieu thu = " + service.calculateTax(product));

        product.setTaxState(new LuxuryTaxState());
        System.out.println("Trang thai thue san pham: " + product.getTaxStateName());
        product.showStateDescription();

        service.setTaxStrategy(new LuxuryTaxStrategy());
        System.out.println("Thue xa xi = " + service.calculateTax(product));

        System.out.println("\nDecorator cong chong nhieu loai thue:");
        PriceComponent finalPrice = new LuxuryTaxDecorator(
                new ConsumptionTaxDecorator(
                        new VATDecorator(
                                new BasePrice(product.getBasePrice())
                        )
                )
        );
        System.out.println("Gia goc: " + product.getBasePrice());
        System.out.println("Gia sau thue: " + finalPrice.getPrice());
    }

    private static void simulatePaymentSystem() {
        PaymentComponent paymentAmount = new DiscountDecorator(
                new ProcessingFeeDecorator(
                        new BasePayment(800000)
                )
        );

        double finalAmount = paymentAmount.getAmount();
        System.out.println("So tien sau khi them phi va giam gia: " + finalAmount);

        PaymentService paymentService = new PaymentService();
        paymentService.setPaymentStrategy(new CreditCardPayment());
        paymentService.pay(finalAmount);

        paymentService.setPaymentStrategy(new PayPalPayment());
        paymentService.pay(finalAmount);

        PaymentTransaction transaction = new PaymentTransaction("PAY001");
        System.out.println("\nTrang thai giao dich: " + transaction.getStateName());
        transaction.process();

        System.out.println("Trang thai giao dich: " + transaction.getStateName());
        transaction.process();
    }

    private static void printConclusion() {
        System.out.println("1. State Pattern phu hop khi doi tuong co nhieu trang thai va hanh vi thay doi theo tung trang thai.");
        System.out.println("2. Strategy Pattern phu hop khi can thay doi thuat toan xu ly linh hoat trong luc chay.");
        System.out.println("3. Decorator Pattern phu hop khi can mo rong tinh nang ma khong sua lop goc.");
        System.out.println("4. Trong bai toan nay, 3 pattern duoc ket hop de tao he thong ro rang, de mo rong va de bao tri hon so voi if-else.");
    }
}