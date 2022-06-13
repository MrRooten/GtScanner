package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.utils.BytesUtils;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class CRLFDetection implements ModuleBase {
    static String payload = "%0d%0aabc:123";

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        var url = new GtURL(webInfo.getUrl());
        IRequestInfo reqInfo = webInfo.getReqInfo();
        List<IParameter> urlParameters = new ArrayList<>();
        List<String> headers = webInfo.getRespInfo().getHeaders();
        for (var parameter : reqInfo.getParameters()) {
            if (parameter.getType() == IParameter.PARAM_URL) {
                for (var header : headers) {
                    if (header.contains(parameter.getValue())) {
                        urlParameters.add(parameter);
                        continue;
                    }
                }
            }
        }

        var session = GtSession.getGlobalSession();
        for (var parameter : urlParameters) {
            var request = new GtRequest(
                    BytesUtils.replaceBytes(webInfo.getRequest(),payload.getBytes(),parameter.getValueStart(), parameter.getValueEnd()),
                    url.isHttps());
            try {
                var response = session.sendRequest(request);
                var respHeaders = response.getHeaders();
                for (var header : respHeaders) {
                    if (header.startsWith("abc:123")) {
                        IScanIssue issue = new GtScanIssue(
                                response.getRequestResponse().getHttpService(),
                                new URL(request.getUrl()),
                                response.getRequestResponse(),
                                "CRLF Detection",
                                "Vulnerable in " + parameter.getName() + ":" + parameter.getValue(),
                                "",
                                Risk.Medium,
                                Confidence.Certain
                        );
                        webInfo.addIssue(issue);
                        callbacks.addScanIssue(issue);
                    }
                }
            } catch (IOException e) {

            }
        }
    }

    @Override
    public Set<String> getTags() {
        return null;
    }
}
