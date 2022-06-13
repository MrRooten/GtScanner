package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;
import okhttp3.Headers;

import java.util.List;

public class JiraRule implements PassiveRule {
    Confidence levelMatch(String respBody, List<String> headers) {
        for (var header : headers) {
            if (header.contains("Location: /secure/SetupMode!default.jspa")) {
                return Confidence.Certain;
            }
        }
        if (respBody.contains("jira.webresources")) {
            return Confidence.Firm;
        }

        if (respBody.contains("ams-build-number")) {
            return Confidence.Firm;
        }

        if (respBody.contains("com.atlassian.jira")) {
            return Confidence.Tentative;
        }

        return null;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        var level = levelMatch(respBody,respInfo.getHeaders());
        if (level != null) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Jira Rule",
                    "Jira Fingerprint",
                    "",
                    Risk.Information,
                    level
            );
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.Jira_Java);
        }
    }
}
