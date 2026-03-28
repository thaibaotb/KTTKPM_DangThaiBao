package tax.state;

import tax.Product;

public class LuxuryTaxState implements ProductTaxState {
    @Override
    public void handle(Product product) {
        System.out.println(product.getName() + ": San pham xa xi, ap dung them thue dac biet.");
    }

    @Override
    public String getStateName() {
        return "Xa xi";
    }
}