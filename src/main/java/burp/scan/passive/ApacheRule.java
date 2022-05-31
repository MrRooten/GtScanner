package burp.scan.passive;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class ApacheRule implements PassiveRule {
    public boolean isApache(String respBody) {
        if (respBody.contains("<title>Test Page for Apache Installation</title>")) {
            return true;
        }

        if (respBody.contains("<TITLE>Test Page for the SSL/TLS-aware Apache Installation on Web Site</TITLE>")) {
            return true;
        }

        if (respBody.contains("<html><body><h1>It works!</h1></body></html>")) {
            return true;
        }

        return false;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks,
                     IHttpRequestResponse baseRequestResponse,
                     String reqBody,
                     String respBody,
                     IRequestInfo reqInfo,
                     IResponseInfo respInfo,
                     String httpServerHeader,
                     String contentTypeResponse,
                     String xPoweredByHeader,
                     WebPageInfo webInfo) {
        if (httpServerHeader!=null && httpServerHeader.toLowerCase().contains("apache")) {
            webInfo.addTag(TagTypes.ApacheHttp_Base);
        }

    }
}
