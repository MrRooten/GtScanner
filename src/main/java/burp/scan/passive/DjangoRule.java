package burp.scan.passive;

import burp.*;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class DjangoRule implements PassiveRule {
    boolean isDjango(String respBody) {
        if (respBody.contains("__admin_media_prefix__") || respBody.contains("csrfmiddlewaretoken")) {
            return true;
        }

        return false;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (isDjango(respBody)) {
            IScanIssue issue = new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Django Fingerprint",
                    "Web is write by Django framework",
                    "",
                    Risk.Information,
                    Confidence.Firm
            );
            webPageInfo.addTag(TagTypes.Django_Python);
            webPageInfo.addIssue(issue);
            callbacks.addScanIssue(issue);
        }
    }
}
