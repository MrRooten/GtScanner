package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class ThinkPHPRule implements PassiveRule {
    boolean isThinkPHP(String xPoweredByHeader,String respBody) {
        if (xPoweredByHeader!=null&&xPoweredByHeader.toLowerCase().contains("thinkphp")) {
            return true;
        }

        if (respBody!=null&&respBody.contains("href=\"http://www.thinkphp.cn\">thinkphp</a>")) {
            return true;
        }

        if (respBody!=null&&respBody.contains("thinkphp_show_page_trace")) {
            return true;
        }

        return false;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (isThinkPHP(xPoweredByHeader,respBody)) {
            IScanIssue issue = new RequestsInfo.CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "ThinkPHP Fingerprint",
                    "Web is write by ThinkPHP framework",
                    "",
                    Risk.Information,
                    Confidence.Firm
            );
            webPageInfo.addTag(TagTypes.ThinkPHP_PHP);
            webPageInfo.addIssue(issue);
            callbacks.addScanIssue(issue);
        }
    }
}
