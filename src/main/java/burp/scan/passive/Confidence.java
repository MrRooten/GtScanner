package burp.scan.passive;

public enum Confidence {

    Certain("Certain"), Firm("Firm"), Tentative("Tentative");
    private String confidence;

    private Confidence(String confidence) {
        this.confidence = confidence;

    }
}
