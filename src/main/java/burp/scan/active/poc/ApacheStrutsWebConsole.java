package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.Confidence;
import burp.scan.lib.CustomScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.*;

public class ApacheStrutsWebConsole implements ModuleBase, RunOnce {

    private static final String TITLE = "Apache Struts - OGNL Console";
    private static final String DESCRIPTION = "J2EEscan identified the Apache Struts Web Console. <br />"
            + "This development console allows the evaluation of OGNL expressions that could lead to Remote Command Execution";
    private static final String REMEDY = "Restrict access to the struts console on the production server";

    private static final byte[] GREP_STRING = "title>OGNL Console".getBytes();
    private static final List<String> STRUTS_WEBCONSOLE_PATHS = Arrays.asList(
            "/struts/webconsole.html?debug=console"
    );

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();

    private PrintWriter stderr;

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        IHttpRequestResponse baseRequestResponse = webInfo.getHttpRequestResponse();
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

            List<String> STRUTS_WEBCONSOLE_PATHS_MUTATED = URIMutator(STRUTS_WEBCONSOLE_PATHS);
            for (String webconsole_path : STRUTS_WEBCONSOLE_PATHS_MUTATED) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), webconsole_path);
                    byte[] webconsoleRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), webconsoleRequest);

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

        /**
         * Test on the application context
         *
         * Ex: http://www.example.com/myapp/Login
         *
         * Retrieve the myapp context and test the issue
         *
         * Ex: http://www.example.com/myapp/struts/webconsole.html
         */
        String context = getApplicationContext(url);

        if (context.isEmpty()) {
            webInfo.addIssues(issues);
            return ;
        }

        String contextURI = system + context;

        if (!hsc.contains(contextURI)) {

            hsc.add(contextURI);

            for (String webconsole_path : STRUTS_WEBCONSOLE_PATHS) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), context + webconsole_path);
                    byte[] webconsoleRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), webconsoleRequest);

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
        webInfo.addIssues(issues);
        return ;
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.Struts_Java));
        return tags;
    }
}

