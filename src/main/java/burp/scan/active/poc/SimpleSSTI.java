package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.Debug;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.utils.Logger;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;


public class SimpleSSTI implements ModuleBase, Debug {
    static String[] payloads = {
            "{{123*1234}}",
            "${123*1234}}"
    };
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        GtURL url = new GtURL(webInfo.getUrl());
        var request = new GtRequest(webInfo.getRequest(),url.isHttps());
        var parameters = request.getParameters();
        Logger logger = Logger.getLogger(this);
        List<IParameter> willTestList = new ArrayList<>();
        var session = GtSession.getGlobalSession();
        for (var parameter : parameters) {
            logger.debug(parameter.getName()+":"+parameter.getValue());
            if (parameter.getValue().contains("*")) {
                willTestList.add(parameter);
            }
        }

        for (var parameter : willTestList) {
            for (var payload : payloads) {
                var rawBytes = request.raw();
                var sstiRequest = new GtRequest(rawBytes,url.isHttps()).
                        setRawSlice(parameter.getValueStart(),parameter.getValueEnd(),payload.getBytes());
                logger.debug("\n"+new String(sstiRequest.raw()));
                try {
                    var response = session.sendRequest(sstiRequest);
                    String res = new String(response.raw());
                    if (res.contains("151782")) {
                        var issue = new GtScanIssue(
                                request.getHttpService(),
                                url.getURL(),
                                response.getRequestResponse(),
                                "Simple SSTI Detection",
                                "The payload is " + payload + " in " + parameter.getName(),
                                "",
                                Risk.High,
                                Confidence.Certain
                        );
                        webInfo.addIssue(issue);

                    }
                } catch (IOException e) {
                    logger.error(e.getMessage());
                }
            }
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
