package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class DrupalRule implements PassiveRule {
    Confidence levelMatch(String respBody,String url) {
        if (url.contains("/misc/drupal.js")) {
            return Confidence.Certain;
        }

        if (respBody.contains("jquery.extend(drupal.settings") || respBody.contains("Powered by <a href=\"https://www.drupal.org\">Drupal</a>")) {
            return Confidence.Certain;
        }

        if (url.contains("/sites/default/files/") || url.contains("/sites/all/themes/") || url.contains("/sites/all/modules/")) {
            return Confidence.Firm;
        }

        return null;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        var level = levelMatch(respBody,reqInfo.getUrl().toString());
        if (level != null) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Drupal Rule",
                    "Drupal Fingerprint",
                    "",
                    Risk.Information,
                    level
            );
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.Drupal_PHP);
        }
    }
}
