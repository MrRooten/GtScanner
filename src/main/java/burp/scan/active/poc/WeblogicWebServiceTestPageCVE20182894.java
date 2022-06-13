package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.Confidence;
import burp.scan.lib.CustomHttpRequestResponse;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.getMatches;

public class WeblogicWebServiceTestPageCVE20182894 implements ModuleBase, RunOnce {
    private static final String TITLE = "Weblogic - Web Service Test Page - Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a potential remote command execution the Weblogic \"Web Service Test Page\".<br />"
            + "The vulnerability is affecting the Web Services (WLS) subcomponent. <br />"
            + "The path: <code>/ws_utc/config.do</code> is by default reachable without any authentication when Weblogic is configured in <b>development mode</b>.<br />"
            + "The Weblogic \"Web Service Test Page\" is vulnerable to an arbitrary file upload vulnerability which leads to a remote command execution.<br />"
            + "Due to the nature of the issue, this check did not tried to exploit the issue. "
            + "<b>References:</b>"
            + "<ul>"
            + "<li>https://nvd.nist.gov/vuln/detail/CVE-2018-2894</li>"
            + "<li>https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/WebLogic%20CVE-2018-2894.py</li>"
            + "<li>https://github.com/111ddea/cve-2018-2894</li>"
            + "</ul>";

    private static final String REMEDY = "Update the Weblogic componenent with the last security patches provided by Oracle. <br />"
            + "Enable Web Service Test Page <code>disabled</code> in (Console -> domain -> advanced).";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;

    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "<title>settings</title>".getBytes()
    );

    private static final List<String> WS_TEST_PAGES = Arrays.asList(
            "/ws_utc/config.do"
    );

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        List<IScanIssue> issues = new ArrayList<>();
        var baseRequestResponse = webInfo.getHttpRequestResponse();
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

            for (String WS_TEST_PAGE : WS_TEST_PAGES) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), WS_TEST_PAGE);
                    byte[] udditest = helpers.buildHttpRequest(urlToTest);
                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, udditest);

                    IResponseInfo wsInfo = helpers.analyzeResponse(response);

                    if (wsInfo.getStatusCode() == 200) {
                        for (byte[] GREP_STRING : GREP_STRINGS) {

                            List<int[]> matches = getMatches(response, GREP_STRING, helpers);

                            if (matches.size() > 0) {
                                issues.add(new GtScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        reqInfo.getUrl(),
                                        new CustomHttpRequestResponse(udditest, response, baseRequestResponse.getHttpService()),
                                        TITLE,
                                        DESCRIPTION,
                                        REMEDY,
                                        Risk.High,
                                        Confidence.Tentative
                                ));
                            }
                        }
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }

                webInfo.addIssues(issues);
                return ;
            }

        }

        webInfo.addIssues(issues);
        return ;
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.WebLogic_Java));
        return tags;
    }
}
