package burp.scan.passive;

import burp.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

import java.util.List;

public class ShiroRule implements PassiveRule {
    boolean isShiro(IHttpRequestResponse baseRequestResponse,IRequestInfo requestInfo,IExtensionHelpers helpers) {

        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            if (header.toLowerCase().contains("rememberme")&&header.toLowerCase().contains("cookie")) {
                return true;
            }
        }


        List<String> respHeaders = helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders();
        for (String header : respHeaders) {
            if (header.toLowerCase().contains("rememberme")&&header.toLowerCase().contains("set-cookie")) {
                return true;
            }
        }

        return false;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks,
                     IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody,
                     IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader,
                     WebPageInfo webInfo) {
        IExtensionHelpers helpers = callbacks.getHelpers();

        if (isShiro(baseRequestResponse,reqInfo,helpers)) {
            webInfo.addTag(TagTypes.Shiro_Java);
        }

    }
}
