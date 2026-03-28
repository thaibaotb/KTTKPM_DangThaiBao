package tax;

import tax.state.NormalTaxState;
import tax.state.ProductTaxState;

public class Product {
    private String name;
    private double basePrice;
    private ProductTaxState taxState;

    public Product(String name, double basePrice) {
        this.name = name;
        this.basePrice = basePrice;
        this.taxState = new NormalTaxState();
    }

    public String getName() {
        return name;
    }

    public double getBasePrice() {
        return basePrice;
    }

    public void setTaxState(ProductTaxState taxState) {
        this.taxState = taxState;
    }

    public ProductTaxState getTaxState() {
        return taxState;
    }

    public String getTaxStateName() {
        return taxState.getStateName();
    }

    public void showStateDescription() {
        taxState.handle(this);
    }
}