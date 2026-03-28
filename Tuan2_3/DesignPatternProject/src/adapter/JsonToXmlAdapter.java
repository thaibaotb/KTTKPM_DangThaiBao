package adapter;

public class JsonToXmlAdapter {
    private XmlService xmlService;

    public JsonToXmlAdapter(XmlService xmlService) {
        this.xmlService = xmlService;
    }

    public void sendJsonAsXml(String jsonData) {
        String xmlData = convertJsonToXml(jsonData);
        xmlService.sendXml(xmlData);
    }

    private String convertJsonToXml(String jsonData) {
        return "<data>" + jsonData.replace("<", "&lt;").replace(">", "&gt;") + "</data>";
    }
}