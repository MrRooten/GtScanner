package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.Confidence;
import burp.scan.issues.IModule;
import burp.scan.lib.*;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPParser.getResponseHeaderValue;

public class HTTPWeakPassword implements IModule{

    private static final String TITLE = "HTTP Weak Password";
    private static final String DESCRIPTION = "J2EEscan identified a remote resource protected"
            + "using HTTP Authentication with a weak password.<br />";

    private static final String REMEDY = "Change the weak/default password";
    
    // List of host and port system already tested
    private LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;


    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebPageInfo webInfo) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        byte[] response = baseRequestResponse.getResponse();
        if (response == null) {
            return issues;
        }

        IResponseInfo respInfo = helpers.analyzeResponse(response);

        URL url = reqInfo.getUrl();
        short responseCode = respInfo.getStatusCode();
        String wwwAuthHeader = getResponseHeaderValue(respInfo, "WWW-Authenticate");
        
        if (responseCode == 401 && wwwAuthHeader != null) {

            // Application path not yet tested for this vulnerability
            if (!hs.contains(url)) {

                hs.add(url);

                // Test Weak Passwords
                CustomHttpRequestResponse httpWeakPasswordResult;
                WeakPasswordBruteforcer br = new WeakPasswordBruteforcer();
                httpWeakPasswordResult = br.HTTPBasicBruteforce(callbacks, url);

                // Retrieve the weak credentials
                String weakCredential = null;
                String weakCredentialDescription = "";
                String bc = null;
                try {

                    IRequestInfo reqInfoPwd = callbacks.getHelpers().analyzeRequest(baseRequestResponse.getHttpService(), httpWeakPasswordResult.getRequest());
                    bc = HTTPParser.getHTTPBasicCredentials(reqInfoPwd);
                    weakCredential = new String(helpers.base64Decode(bc));
                } catch (Exception ex) {
                    stderr.println("HTTP Weak Password - Error during Authorization Header parsing " + ex + bc);
                }

                if (weakCredential != null) {
                    weakCredentialDescription += String.format("<br /><br /> The weak credentials are "
                            + "<b>%s</b><br /><br />", weakCredential);
                }

                if (httpWeakPasswordResult != null) {
                    issues.add(new RequestsInfo.CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            url,
                            httpWeakPasswordResult,
                            TITLE,
                            DESCRIPTION + weakCredentialDescription,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));

                }

            }

        }
        
        return issues;
    }
}
