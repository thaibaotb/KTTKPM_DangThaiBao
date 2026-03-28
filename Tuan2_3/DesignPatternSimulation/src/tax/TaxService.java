package tax;

import tax.strategy.TaxStrategy;

public class TaxService {
    private TaxStrategy taxStrategy;

    public void setTaxStrategy(TaxStrategy taxStrategy) {
        this.taxStrategy = taxStrategy;
    }

    public double calculateTax(Product product) {
        return taxStrategy.calculateTax(product.getBasePrice());
    }
}