package burp.scan.passive;

import burp.*;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.Risk;
import burp.scan.lib.WebInfo;
import burp.scan.tags.TagTypes;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

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
                     WebInfo webInfo) {
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        WebInfo info = new WebInfo();
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