package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.WebInfo;
import burp.scan.passive.Confidence;
import burp.scan.issues.IModule;
import burp.scan.lib.Risk;
import burp.scan.passive.CustomScanIssue;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.getMatches;

public class ApacheStrutsShowcase implements IModule {

    private static final String TITLE = "Apache Struts - ShowCase Application";
    private static final String DESCRIPTION = "J2EEscan identified the Apache Struts ShowCase application. <br />"
            + "Based on the installed version, the application could be vulnerable to different kind of issues"
            + " such as XSS, RCE via OGNL injection, etc.<br /><br />"
            + "<b>References:</b><br />"
            + "https://bugzilla.redhat.com/show_bug.cgi?id=967655<br />"
            + "http://struts.apache.org/docs/s2-012.html";

    private static final String REMEDY = "Remove all unused applications from production environment";

    private static final byte[] GREP_STRING = "<title>Struts2 Showcase</title>".getBytes();
    private static final List<String> STRUTS_SHOWCASE_PATHS = Arrays.asList(
            "/struts2-showcase/showcase.action"
    );

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebInfo webInfo) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();
        String protocol = url.getProtocol();

        String system = host.concat(Integer.toString(port));

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            for (String SHOWCASE_PATH : STRUTS_SHOWCASE_PATHS) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), SHOWCASE_PATH);
                    byte[] showcaseRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), showcaseRequest);

                    byte[] response = checkRequestResponse.getResponse();
                    IResponseInfo responseInfo = helpers.analyzeResponse(response);

                    if (responseInfo.getStatusCode() == 200) {
                        // look for matches of our active check grep string
                        List<int[]> matches = getMatches(response, GREP_STRING, helpers);

                        if (matches.size() > 0) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    reqInfo.getUrl(),
                                    checkRequestResponse,
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));
                        }
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Error creating URL " + ex.getMessage());
                }
            }
        }

        return issues;
    }
}
