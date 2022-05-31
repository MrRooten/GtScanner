package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class ConfluenceRule implements PassiveRule {
    boolean isConfluence(IResponseInfo respInfo,String respBody) {
        var headers = respInfo.getHeaders();
        for (String header : headers) {
            if (header.contains("Location: /login.action?os_destination=")) {
                return true;
            }

            if (header.contains("X-Confluence-Request-Time: '*'")) {
                return true;
            }
        }

        if (respBody.contains("id=\"com-atlassian-confluence")) {
            return true;
        }

        if (respBody.contains("name=\"confluence-base-url\"")) {
            return true;
        }

        return false;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (isConfluence(respInfo,respBody)) {
            IScanIssue issue = new RequestsInfo.CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Confluence Fingerprint",
                    "This is a Confluence Service",
                    "",
                    Risk.Information,
                    Confidence.Certain
            );
            webPageInfo.addTag(TagTypes.Confluence_Java);
            webPageInfo.addIssue(issue);
            callbacks.addScanIssue(issue);
        }
    }
}
