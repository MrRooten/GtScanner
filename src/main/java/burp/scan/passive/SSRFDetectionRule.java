package burp.scan.passive;

import burp.*;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SSRFDetectionRule implements PassiveRule {
    static final String SSRF_PATTERN = "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        var parser = webPageInfo.getParser();
        var parameters = parser.getParameters();
        Pattern pattern = Pattern.compile(SSRF_PATTERN);
        for (var parameter : parameters) {
            Matcher matcher = pattern.matcher(parameter.getValue());
            if (matcher.find()) {
                IScanIssue issue = new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "SSRF Passive Scan",
                        "",
                        "",
                        Risk.High,
                        Confidence.Tentative
                );
                callbacks.addScanIssue(issue);
                webPageInfo.addTag(TagTypes.SSRF_Base);
            }
        }
    }
}
