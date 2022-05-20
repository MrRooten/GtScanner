package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.WebInfo;
import burp.scan.passive.Confidence;
import burp.scan.issues.IModule;
import burp.scan.lib.Risk;
import burp.scan.passive.CustomScanIssue;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.getMatches;

public class ApacheWicketArbitraryResourceAccess implements IModule {

    private static final String TITLE = "Apache Wicket - Arbitrary Resource Access";
    private static final String DESCRIPTION = "J2EEScan identified a vulnerable Apache Wicket library; "
            + "it's possible to access remotely to arbitrary resources in"
            + " the classpath of the wicket application using the <i>int</i> scope<br /><br />"
            + "<b>References</b>:<br />"
            + "https://issues.apache.org/jira/browse/WICKET-4427<br />"
            + "https://issues.apache.org/jira/browse/WICKET-4430";

    private static final String REMEDY = "Update the remote Apache Wicket vulnerable library";

    private static final byte[] GREP_STRING = "initializer=".getBytes();
    private static final List<String> PAYLOADS = Arrays.asList(
            "wicket/resource/int/wicket.properties,/bla/ HTTP",
            "wicket/resources/int/wicket.properties,/bla/ HTTP"
    );

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebInfo webInfo) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        
        if (curURL.getPath().contains("wicket/resource")) {
            byte[] rawrequest = baseRequestResponse.getRequest();
            String plainRequest = helpers.bytesToString(rawrequest);

            for (String payload : PAYLOADS) {
                
                byte[] wicketRequest = helpers.stringToBytes(plainRequest.replaceFirst("wicket\\/resource.*? HTTP", payload));

                IRequestInfo rawWicketRequestInfo = helpers.analyzeRequest(wicketRequest);

                List<String> headers = rawWicketRequestInfo.getHeaders();
                byte message[] = helpers.buildHttpMessage(headers, Arrays.copyOfRange(wicketRequest, rawWicketRequestInfo.getBodyOffset(), wicketRequest.length));
                IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);

                // look for matches of our active check grep string in the response body
                byte[] httpResponse = resp.getResponse();
                List<int[]> matches = getMatches(httpResponse, GREP_STRING, helpers);
                if (matches.size() > 0) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            resp,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));

                    return issues;
                }
            }
        }

        return issues;

    }
}