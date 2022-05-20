package burp.scan.passive;

import burp.*;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

import java.io.PrintWriter;

public class NginxRule implements PassiveRule{
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
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        WebPageInfo info = new WebPageInfo();
        if (httpServerHeader == null) {
            return ;
        }

        if (httpServerHeader.toLowerCase().contains("nginx")) {
            info.addTag(TagTypes.Nginx_Base);
        }

        RequestsInfo requestsInfo = RequestsInfo.getInstance();
        requestsInfo.putInfo(reqInfo,info);
    }
}
