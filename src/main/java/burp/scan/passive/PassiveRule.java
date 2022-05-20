package burp.scan.passive;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.scan.lib.WebInfo;

public interface PassiveRule {


    void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
              String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
              String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebInfo webInfo);
}