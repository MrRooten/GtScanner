package burp.scan.lib.poc;

import burp.IBurpCollaboratorInteraction;

import java.util.Map;

public class PocResult {
    Map<String,String> properties;
    String payload;
    public PocResult(Map<String,String> properties,String payload) {
        this.payload = payload;
        this.properties = properties;
    }

    public Map<String,String> getProperties() {
        return properties;
    }
}
