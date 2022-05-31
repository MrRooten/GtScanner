package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

import java.util.List;

public class LaravelRule implements PassiveRule {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        List<String> headers = respInfo.getHeaders();
        for (var header : headers) {
            if (header.startsWith("Set-Cookie:")&&header.contains("laravel_session")) {
                IScanIssue issue = new RequestsInfo.CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Laravel Fingerprint",
                        "Web is write by Laravel framework",
                        "",
                        Risk.Information,
                        Confidence.Certain
                );
                webPageInfo.addTag(TagTypes.Laravel_PHP);
                webPageInfo.addIssue(issue);
                callbacks.addScanIssue(issue);
            }
        }
    }
}
