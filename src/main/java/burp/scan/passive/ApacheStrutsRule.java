package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class ApacheStrutsRule implements PassiveRule {
    Confidence levelStruts(String respBody) {
        if (respBody.contains("content=\"Struts2 Showcase for Apache Struts Project\"")) {
            return Confidence.Certain;
        }

        if (respBody.contains("struts problem report") ||
                respBody.contains("there is no action mapped for namespace") ||
                respBody.contains("no result defined for action and result input")) {
            return Confidence.Firm;
        }

        return null;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        Confidence level = levelStruts(respBody);
        if (level != null) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Apache Struts Fingerprint",
                    "This is running in Struts service",
                    "",
                    Risk.Information,
                    level
            );
            callbacks.addScanIssue(issue);
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.Struts_Java);
        }
    }
}
