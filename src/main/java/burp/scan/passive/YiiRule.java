package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class YiiRule implements PassiveRule {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (respBody.contains("yii_csrf_token")) {
            IScanIssue issue = new RequestsInfo.CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Yii Fingerprint",
                    "Web is write by Yii framework",
                    "",
                    Risk.Information,
                    Confidence.Firm
            );
            webPageInfo.addTag(TagTypes.Yii_PHP);
            webPageInfo.addIssue(issue);
            callbacks.addScanIssue(issue);
        }
    }
}
