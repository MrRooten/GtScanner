package burp.scan.lib.poc;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.scan.lib.GlobalFunction;

import java.util.ArrayList;
import java.util.List;

public class ReversePocClient {
    IBurpCollaboratorClientContext context;
    String payload;
    public ReversePocClient() {
        context = GlobalFunction.callbacks.createBurpCollaboratorClientContext();
    }

    public String getPayload() {
        payload = context.generatePayload(true);
        return payload;
    }

    public List<PocResult> getResults() {
        List<IBurpCollaboratorInteraction> collaboratorInteractions = context.fetchCollaboratorInteractionsFor(payload);
        List<PocResult> results = new ArrayList<>();
        for (var interaction : collaboratorInteractions) {
            results.add(new PocResult(interaction,payload));
        }
        return results;
    }
}
