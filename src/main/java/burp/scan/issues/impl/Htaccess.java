package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.WebInfo;
import burp.scan.passive.Confidence;
import burp.scan.annotation.RunOnlyOnce;
import burp.scan.issues.IModule;
import burp.scan.lib.CustomHttpRequestResponse;
import burp.scan.lib.Risk;
import burp.scan.passive.CustomScanIssue;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.getMatches;


/**
 * Check for /.htaccess Detection
 * 
 * 
 * TODO
 *  - Improve detection strategy
 * 
 */
public class Htaccess implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private static final String HTACCESS_PATH =  "/.htaccess";

    // TODO improve pattern matching detection
    private static final byte[] GREP_STRING = "RewriteEngin".getBytes();

    private static final String TITLE = ".htaccess Accessible";
    private static final String DESCRIPTION = "J2EEscan identified the .htaccess file";

    private static final String REMEDY = "Restrict access to the resource using proper ACL restriction";

    private PrintWriter stderr;

    @RunOnlyOnce
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebInfo webInfo) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();

        String system = host.concat(Integer.toString(port));

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            try {

                URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), HTACCESS_PATH);
                byte[] htaccesstest = helpers.buildHttpRequest(urlToTest);

                byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                        url.getPort(), isSSL, htaccesstest);

                IResponseInfo htaccessInfo = helpers.analyzeResponse(responseBytes);

                if (htaccessInfo.getStatusCode() == 200) {

                    List<int[]> matchHtaccess = getMatches(responseBytes, GREP_STRING, helpers);

                    if (matchHtaccess.size() > 0) {

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                urlToTest,
                                new CustomHttpRequestResponse(htaccesstest, responseBytes, baseRequestResponse.getHttpService()),
                                TITLE,
                                DESCRIPTION,
                                REMEDY,
                                Risk.Low,
                                Confidence.Certain
                        ));
                        return issues;
                    }
                }

                byte[] rawRequest = baseRequestResponse.getRequest();
                IRequestInfo reqInfoHTTPVerbTampering = helpers.analyzeRequest(baseRequestResponse);

                // Remove Authorization HTTP Header
                List<String> headers = reqInfoHTTPVerbTampering.getHeaders();
                for (int h = 0; h < headers.size(); h++) {
                    if (headers.get(h).toLowerCase().startsWith("authorization".toLowerCase())) {
                        headers.remove(h);
                    }
                }

                // Change HTTP verb for GET requests to GETS to bypass possible
                // HTTP VERB restriction
                if (headers.get(0).toLowerCase().startsWith("get ".toLowerCase())) {
 
                    headers.set(0, "GETS /.htaccess HTTP/1.1");
                    byte message[] = helpers.buildHttpMessage(headers, Arrays.copyOfRange(rawRequest,
                            reqInfoHTTPVerbTampering.getBodyOffset(), rawRequest.length));

                    IHttpRequestResponse respHTTPVerbTampering = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                            message);

                    IResponseInfo modifiedHTTPVerbTamperingResponseInfo = helpers.analyzeResponse(respHTTPVerbTampering.getResponse());
                    if (modifiedHTTPVerbTamperingResponseInfo.getStatusCode() == 200) {

                        List<int[]> matchHTTPVerbTamperingHtaccess = getMatches(respHTTPVerbTampering.getResponse(),
                                "<Limit".getBytes(), helpers);

                        if (matchHTTPVerbTamperingHtaccess.size() > 0) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), HTACCESS_PATH),
                                    respHTTPVerbTampering,
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));
                            return issues;

                        }
                    }

                }

            } catch (MalformedURLException ex) {
                stderr.println("Malformed URI exception " + ex);

            }
        }

        return issues;
    }
}
