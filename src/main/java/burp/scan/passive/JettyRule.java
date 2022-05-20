package burp.scan.passive;

import burp.*;
import burp.scan.lib.Risk;
import burp.scan.lib.WebInfo;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JettyRule implements PassiveRule {

    private static final Pattern JETTY_PATTERN = Pattern.compile("><small>Powered by Jetty", Pattern.DOTALL | Pattern.MULTILINE);
    
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader,
                     WebInfo webInfo) {
        IExtensionHelpers helpers = callbacks.getHelpers();

        /**
         * Detect Jetty
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {

            
            Matcher matcher = JETTY_PATTERN.matcher(respBody);

            if (matcher.find()) {
              
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Jetty",
                        "J2EEscan identified the remote Servlet Container",
                        "",
                        Risk.Information,
                        Confidence.Certain
                ));
            }

        }
  
    }
}
