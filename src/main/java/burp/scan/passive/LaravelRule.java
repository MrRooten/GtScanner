package burp.scan.passive;

import burp.*;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

import java.util.List;

public class LaravelRule implements PassiveRule {
    boolean isLaravelDebug(String respBody,int status,List<String> headers) {
        if (status == 405 && (respBody.contains("MethodNotAllowedHttpException")||
                respBody.contains("Environment &amp; details"))) {
            return true;
        }

        return false;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        List<String> headers = respInfo.getHeaders();
        for (var header : headers) {
            if ((header.startsWith("Set-Cookie:")&&header.contains("laravel_session")) ||
                    webPageInfo.getUrl().contains("_ignition/execute-solution")) {
                IScanIssue issue = new GtScanIssue(
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

        if (isLaravelDebug(respBody,respInfo.getStatusCode(),respInfo.getHeaders())) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Laravel Debug",
                    "Laravel work in debug mode",
                    "",
                    Risk.Information,
                    Confidence.Certain
            );
            webPageInfo.addTag(TagTypes.LaravelDebug_Laravel);
            webPageInfo.addIssue(issue);
            callbacks.addScanIssue(issue);
        }
    }
}
