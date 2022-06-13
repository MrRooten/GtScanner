package burp.scan.passive;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.scan.java.strutstoken.StrutsTokenCracker;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rule that identify Struts S2-023
 * <br/>
 * Ref: http://struts.apache.org/docs/s2-023.html
 *
 * @author Philippe Arteau
 */
public class ApacheStrutsS2023Rule implements PassiveRule {

    private final Pattern TOKEN_FIELD_PATTERN = Pattern.compile("<input type=\"hidden\" name=\"token\" value=\"([^\"]+)\"");

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader,
                     WebPageInfo webInfo) {

        //IExtensionHelpers helpers = callbacks.getHelpers();

        Matcher m = TOKEN_FIELD_PATTERN.matcher(respBody);
        if(m.find())
        {
            String tokenValue = m.group(1);
            boolean isVulnerable = StrutsTokenCracker.testToken(tokenValue);

            if(isVulnerable) {
                callbacks.addScanIssue(new GtScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Apache Struts S2-023 Predictable CSRF Token",
                        "The CSRF tokens of the Struts application can be predicted. "
                                + "The attacker make a specially craft form using the predicted token that force an action to a logged-in user (CSRF).\n"
                                + "<br/><br/>"
                                + "<b>References</b>:<br /><br />"
                                + "http://struts.apache.org/docs/s2-023.html<br />"
                                + "http://blog.h3xstream.com/2014/12/predicting-struts-csrf-token-cve-2014.html<br />",
                        "Update the remote Struts vulnerable library",
                        Risk.Medium,
                        Confidence.Certain
                ));
            }
        }
    }

}
