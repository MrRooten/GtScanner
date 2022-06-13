package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class GogsRule implements PassiveRule {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (respBody.contains("<a class=\"item\" target=\"_blank\" href=\"https://gogs.io/docs\" rel=\"noreferrer\">") ||
                respBody.contains("content=\"gogs")) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Gogs Fingerprint",
                    "May have CVE-2018-18925,CVE-2022-0415",
                    "",
                    Risk.Information,
                    Confidence.Certain
            );
            callbacks.addScanIssue(issue);
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.Gogs_Golang);
        }
    }
}
