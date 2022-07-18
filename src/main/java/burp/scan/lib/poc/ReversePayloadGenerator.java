package burp.scan.lib.poc;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.scan.lib.GlobalFunction;

import java.util.ArrayList;
import java.util.List;

public class ReversePayloadGenerator {
    IBurpCollaboratorClientContext context;
    String payload;
    public ReversePayloadGenerator() {
        context = GlobalFunction.callbacks.createBurpCollaboratorClientContext();
    }

    static ReversePayloadGenerator generator = null;

    static public ReversePayloadGenerator getInstance() {
        if (generator == null) {
            generator = new ReversePayloadGenerator();
        }
        return generator;
    }
    public String getReverseUrl() {
        String payload = context.generatePayload(true);
        return payload;
    }

    public List<PocResult> getResults(String payload) {
        List<IBurpCollaboratorInteraction> collaboratorInteractions = context.fetchCollaboratorInteractionsFor(payload);
        List<PocResult> results = new ArrayList<>();
        for (var interaction : collaboratorInteractions) {
            results.add(new PocResult(interaction.getProperties(),payload));
        }
        return results;
    }

}
