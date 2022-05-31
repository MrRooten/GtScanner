package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

import java.util.regex.Pattern;

public class JettyRule implements PassiveRule {

    private static final Pattern JETTY_PATTERN = Pattern.compile("><small>Powered by Jetty", Pattern.DOTALL | Pattern.MULTILINE);

    boolean isJetty(String resBody,String httpServerHeader) {
        if (httpServerHeader!=null && httpServerHeader.toLowerCase().contains("jetty")) {
            return true;
        }

        if (resBody!=null&&resBody.contains("Powered by Jetty://")) {
            return true;
        }

        if (resBody!=null&&JETTY_PATTERN.matcher(resBody).find()) {
            return true;
        }

        return false;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader,
                     WebPageInfo webInfo) {
        IExtensionHelpers helpers = callbacks.getHelpers();

        /**
         * Detect Jetty
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {

            


            if (isJetty(respBody,httpServerHeader)) {
                RequestsInfo.CustomScanIssue issue = new RequestsInfo.CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Jetty",
                        "J2EEscan identified the remote Servlet Container",
                        "",
                        Risk.Information,
                        Confidence.Certain
                );
                callbacks.addScanIssue(issue);
                webInfo.addIssue(issue);
                webInfo.addTag(TagTypes.Jetty_Java);
            }

        }
  
    }
}
