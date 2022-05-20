package burp.scan.passive;

import burp.*;
import burp.scan.lib.web.WebPageInfo;

import java.nio.charset.StandardCharsets;

public class StrutsRule implements PassiveRule{

    boolean isStruts(IExtensionHelpers helpers, WebPageInfo webInfo) {
        String resBody = new String(webInfo.getResponse(), StandardCharsets.UTF_8);
        if (resBody.contains("content=\"Struts2 Showcase for Apache Struts Project\"")) {
            return true;
        }

        if (resBody.contains("struts problem report")) {
            return true;
        }

        if (resBody.contains("there is no action mapped for namespace")) {
            return true;
        }

        if (resBody.contains("no result defined for action and result input")) {
            return true;
        }

        return false;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webInfo) {

    }
}
