package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class GrafanaRule implements PassiveRule {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (respBody.contains("window.grafanabootdata =")) {
            IScanIssue issue = new RequestsInfo.CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Grafana Fingerprint",
                    "This is a Grafana Service",
                    "",
                    Risk.Information,
                    Confidence.Certain
            );
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.Grafana_Base);
            callbacks.addScanIssue(issue);
        }
    }
}
