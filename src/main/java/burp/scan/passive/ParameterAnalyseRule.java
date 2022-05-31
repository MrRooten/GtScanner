package burp.scan.passive;

import burp.*;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.web.WebPageInfo;

public class ParameterAnalyseRule implements PassiveRule {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {

    }
}
