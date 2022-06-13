package burp.scan.passive;

import burp.*;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;

public class ApacheSolrRule implements PassiveRule {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        GtURL u = new GtURL(reqInfo.getUrl().toString());
        String baseUrl = u.getFileDir();
        if (baseUrl.contains("/solr/")) {
            webPageInfo.addTag(TagTypes.Solr_Java);
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Solr Fingerprint",
                    "This is a Solr Service",
                    "",
                    Risk.Information,
                    Confidence.Certain
            );
            webPageInfo.addIssue(issue);
        }

    }
}
