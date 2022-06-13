package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class MiniHttpdRule implements PassiveRule {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (httpServerHeader.contains("mini_httpd")) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Mini httpd Fingerprint",
                    "May have CVE-2018-18778",
                    "",
                    Risk.Information,
                    Confidence.Certain
            );
            callbacks.addScanIssue(issue);
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.MiniHttpd_Base);
        }
    }
}
