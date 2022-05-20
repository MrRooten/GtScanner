package burp.scan.passive;

import burp.*;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.WebInfo;
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
                     WebInfo webInfo) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        WebInfo info = new WebInfo();
        if (isShiro(baseRequestResponse,requestInfo,helpers)) {
            info.addTag(TagTypes.Shiro_Java);
        }
        RequestsInfo.getInstance().putInfo(requestInfo,info);

    }
}
