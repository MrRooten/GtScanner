package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.Disable;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;

import java.io.IOException;
import java.net.URL;
import java.util.Set;

public class Test implements ModuleBase {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        String url = webInfo.getUrl();
        GtSession session = GtSession.getGlobalSession();
        callbacks.printOutput("This is test");
        session.setBurpRequest();
            GtRequest request = new GtRequest(url);
            try {
                var resp = session.sendRequest(request);
                IScanIssue issue = new GtScanIssue(
                        resp.getRequestResponse().getHttpService(),
                        new URL(url),
                        resp.getRequestResponse(),
                        "Test Unit",
                        "Test",
                        "",
                        Risk.High,
                        Confidence.Certain
                );
                webInfo.addIssue(issue);
                callbacks.addScanIssue(issue);
            } catch (IOException e) {
                callbacks.printError(e.getLocalizedMessage());
            }

    }

    @Override
    public Set<String> getTags() {
        return null;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
