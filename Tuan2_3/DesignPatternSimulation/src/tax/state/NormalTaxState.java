package tax.state;

import tax.Product;

public class NormalTaxState implements ProductTaxState {
    @Override
    public void handle(Product product) {
        System.out.println(product.getName() + ": San pham thong thuong, ap dung muc thue co ban.");
    }

    @Override
    public String getStateName() {
        return "Thong thuong";
    }
}