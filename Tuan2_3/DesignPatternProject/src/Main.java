import java.util.List;

import composite.filesystem.FileLeaf;
import composite.filesystem.FolderComposite;
import composite.ui.Button;
import composite.ui.Dialog;
import composite.ui.NavigationBar;
import composite.ui.UIGroup;

import observer.stock.Investor;
import observer.stock.Stock;
import observer.task.Task;
import observer.task.TeamMember;

import adapter.JsonService;
import adapter.JsonToXmlAdapter;
import adapter.XmlService;
import adapter.XmlToJsonAdapter;

import library.core.Book;
import library.core.Library;
import library.decorator.Borrowable;
import library.decorator.BrailleVersionDecorator;
import library.decorator.ExtendBorrowDecorator;
import library.decorator.TranslatedVersionDecorator;
import library.factory.BookFactory;
import library.factory.SimpleBookFactory;
import library.observer.Librarian;
import library.observer.Subscriber;
import library.service.LibraryService;
import library.strategy.SearchByAuthor;
import library.strategy.SearchByCategory;
import library.strategy.SearchByTitle;
import library.strategy.SearchContext;

public class Main {
    public static void main(String[] args) {
        demoCompositeFileSystem();
        demoCompositeUI();
        demoObserverStock();
        demoObserverTask();
        demoAdapter();
        demoLibrarySystem();
    }

    private static void demoCompositeFileSystem() {
        System.out.println("===== COMPOSITE: FILE SYSTEM =====");

        FolderComposite root = new FolderComposite("root");
        FolderComposite documents = new FolderComposite("documents");
        FolderComposite images = new FolderComposite("images");

        FileLeaf file1 = new FileLeaf("report.docx", 120);
        FileLeaf file2 = new FileLeaf("photo.jpg", 450);
        FileLeaf file3 = new FileLeaf("notes.txt", 30);

        documents.add(file1);
        documents.add(file3);
        images.add(file2);

        root.add(documents);
        root.add(images);

        root.display("");
        System.out.println();
    }

    private static void demoCompositeUI() {
        System.out.println("===== COMPOSITE: UI =====");

        UIGroup mainScreen = new UIGroup("Main Screen");
        UIGroup header = new UIGroup("Header");
        UIGroup body = new UIGroup("Body");

        header.add(new NavigationBar("Top Navigation"));
        body.add(new Button("Login Button"));
        body.add(new Dialog("Register Dialog"));

        mainScreen.add(header);
        mainScreen.add(body);

        mainScreen.render("");
        System.out.println();
    }

    private static void demoObserverStock() {
        System.out.println("===== OBSERVER: STOCK =====");

        Stock stock = new Stock("ABC", 100.0);
        Investor inv1 = new Investor("An");
        Investor inv2 = new Investor("Binh");

        stock.registerObserver(inv1);
        stock.registerObserver(inv2);

        stock.setPrice(110.5);
        System.out.println();
    }

    private static void demoObserverTask() {
        System.out.println("===== OBSERVER: TASK =====");

        Task task = new Task("Implement Login", "TODO");
        TeamMember m1 = new TeamMember("Lan");
        TeamMember m2 = new TeamMember("Minh");

        task.registerObserver(m1);
        task.registerObserver(m2);

        task.setStatus("IN PROGRESS");
        task.setStatus("DONE");
        System.out.println();
    }

    private static void demoAdapter() {
        System.out.println("===== ADAPTER =====");

        JsonService jsonService = new JsonService();
        XmlService xmlService = new XmlService();

        XmlToJsonAdapter xmlToJsonAdapter = new XmlToJsonAdapter(jsonService);
        JsonToXmlAdapter jsonToXmlAdapter = new JsonToXmlAdapter(xmlService);

        xmlToJsonAdapter.sendXmlAsJson("<user><name>Nam</name></user>");
        jsonToXmlAdapter.sendJsonAsXml("{\"name\":\"Hoa\"}");
        System.out.println();
    }

    private static void demoLibrarySystem() {
        System.out.println("===== LIBRARY MANAGEMENT SYSTEM =====");

        Library library = Library.getInstance();

        library.registerObserver(new Librarian("Thu Thu A"));
        library.registerObserver(new Subscriber("Doc Gia B"));

        BookFactory factory = new SimpleBookFactory();
        LibraryService service = new LibraryService(library, factory);

        Book b1 = service.addBook("paper", "B01", "Java Core", "James", "Programming");
        Book b2 = service.addBook("ebook", "B02", "Design Patterns", "Gamma", "Software");
        Book b3 = service.addBook("audio", "B03", "Clean Code", "Robert Martin", "Programming");

        service.showAllBooks();
        System.out.println();

        SearchContext context = new SearchContext();

        context.setStrategy(new SearchByTitle());
        List<Book> byTitle = service.searchBooks(context, "Java");
        System.out.println("Tim theo ten:");
        for (Book book : byTitle) {
            System.out.println(book);
        }
        System.out.println();

        context.setStrategy(new SearchByAuthor());
        List<Book> byAuthor = service.searchBooks(context, "Gamma");
        System.out.println("Tim theo tac gia:");
        for (Book book : byAuthor) {
            System.out.println(book);
        }
        System.out.println();

        context.setStrategy(new SearchByCategory());
        List<Book> byCategory = service.searchBooks(context, "Programming");
        System.out.println("Tim theo the loai:");
        for (Book book : byCategory) {
            System.out.println(book);
        }
        System.out.println();

        Borrowable borrow = service.borrowBook(b1);
        borrow = new ExtendBorrowDecorator(borrow);
        borrow = new BrailleVersionDecorator(borrow);
        borrow = new TranslatedVersionDecorator(borrow);

        System.out.println("Mo ta muon sach:");
        System.out.println(borrow.getDescription());
        System.out.println();

        service.returnBook(b1);
        service.markOverdue(b2);
        System.out.println();
    }
}