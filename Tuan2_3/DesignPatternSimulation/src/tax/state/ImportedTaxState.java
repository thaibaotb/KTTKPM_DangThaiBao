package tax.state;

import tax.Product;

public class ImportedTaxState implements ProductTaxState {
    @Override
    public void handle(Product product) {
        System.out.println(product.getName() + ": San pham nhap khau, co the ap dung VAT va thue tieu thu.");
    }

    @Override
    public String getStateName() {
        return "Nhap khau";
    }
}