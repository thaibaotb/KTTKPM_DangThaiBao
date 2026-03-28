package tax.state;

import tax.Product;

public interface ProductTaxState {
    void handle(Product product);
    String getStateName();
}