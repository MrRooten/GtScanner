package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.passive.Confidence;
import burp.scan.issues.IModule;
import burp.scan.lib.Risk;
import burp.scan.passive.CustomScanIssue;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.isJavaApplicationByURL;

public class ApacheStrutsS2017 implements IModule {

    private static final String TITLE = "Apache Struts S2-017 Injection - Arbitrary Redirect";
    private static final String DESCRIPTION = "J2EEscan identified an Arbitrary Redirect vulnerability;"
            + "the Struts 2 DefaultActionMapper supports a "
            + "method for short-circuit navigation state changes by prefixing "
            + "parameters with <i>action:</i> or <i>redirect:</i>, "
            + "followed by a desired navigational target expression. "
            + "This mechanism was intended to help with attaching navigational "
            + "information to buttons within forms.<br /><br />"
            + "In Struts 2 before 2.3.15.1 the information following <i>action:</i>, <i>redirect:</i> "
            + "or <i>redirectAction:</i> is not properly sanitized. "
            + "<br /><br />Since said information will be evaluated as OGNL expression"
            + " against the value stack, this introduces the possibility to inject "
            + "server side code.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/release/2.3.x/docs/s2-017.html<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2248";
    private static final String REMEDY = "Update the remote Struts vulnerable library";

    private PrintWriter stderr;

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebPageInfo webInfo) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        byte[] modifiedRawRequest = null;
        List<IScanIssue> issues = new ArrayList<>();

        if (!isJavaApplicationByURL(curURL)) {
            return issues;
        }

        List<String> redirectMeth = new ArrayList();
        redirectMeth.add("redirect:");
        redirectMeth.add("redirectAction:");

        for (String redir : redirectMeth) {

            try {
                byte[] rawrequest = baseRequestResponse.getRequest();
                List<IParameter> parameters = reqInfo.getParameters();

                //Remove URI parameters
                for (IParameter param : parameters) {
                    rawrequest = callbacks.getHelpers().removeParameter(rawrequest, param);
                }

                rawrequest = callbacks.getHelpers().addParameter(rawrequest,
                        callbacks.getHelpers().buildParameter(redir, "http://www.example.com/%23", IParameter.PARAM_URL)
                );

                //TODO Fix me hack
                String utf8rawRequest = new String(rawrequest, "UTF-8");
                modifiedRawRequest = utf8rawRequest.replaceFirst("=", "").getBytes();

                // make a request containing our injection test in the insertion point
                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(), modifiedRawRequest);

                IResponseInfo modifiedResponseInfo = callbacks.getHelpers().analyzeResponse(checkRequestResponse.getResponse());

                int statusCode = modifiedResponseInfo.getStatusCode();

                if (statusCode >= 300 && statusCode < 400) {
                    for (String header : modifiedResponseInfo.getHeaders()) {
                        if (header.toLowerCase().startsWith("location")) {

                        }
                        if (header.substring(header.indexOf(":") + 1).trim().startsWith("http://www.example.com/")) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    reqInfo.getUrl(),
                                    checkRequestResponse,
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain));
                        }

                    }
                }
            } catch (UnsupportedEncodingException ex) {
                stderr.println(ex);
            }
        }

        return issues;
    }
}
