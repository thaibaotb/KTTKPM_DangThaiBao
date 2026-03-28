package adapter;

public class XmlToJsonAdapter {
    private JsonService jsonService;

    public XmlToJsonAdapter(JsonService jsonService) {
        this.jsonService = jsonService;
    }

    public void sendXmlAsJson(String xmlData) {
        String jsonData = convertXmlToJson(xmlData);
        jsonService.sendJson(jsonData);
    }

    private String convertXmlToJson(String xmlData) {
        return "{ \"convertedFromXml\": \"" + xmlData.replace("\"", "\\\"") + "\" }";
    }
}