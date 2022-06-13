package burp.scan.passive;

import burp.*;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class WebLogicRule implements PassiveRule {
    Confidence isWebLogic(String respBody) {
        if (respBody.contains("<i>Hypertext Transfer Protocol -- HTTP/1.1</i>")) {
            return Confidence.Certain;
        }

        if (respBody.contains("/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png")) {
            return Confidence.Certain;
        }

        if (respBody.contains("Error 404--Not Found")) {
            return Confidence.Firm;
        }

        if (respBody.contains("Error 403--")) {
            return Confidence.Firm;
        }

        return null;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        Confidence level = isWebLogic(respBody);
        if(level != null) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "WebLogic Fingerprint",
                    "Web is a WebLogic service",
                    "",
                    Risk.Information,
                    level
            );
            webPageInfo.addTag(TagTypes.WebLogic_Java);
            webPageInfo.addIssue(issue);
            callbacks.addScanIssue(issue);
        }
    }
}
