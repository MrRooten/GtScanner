package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;

import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.getMatches;

public class ApacheRollerOGNLInjection implements ModuleBase {
    private static final String TITLE = "Apache Roller OGNL Injection";
    private static final String DESCRIPTION = "J2EEscan identified an OGNL  "
            + "Injection vulnerability. <br />Apache Roller is a full-featured, multi-user "
            + "and group-blog server suitable for blog sites large and small. "
            + "It runs as a Java web application that should be able to run on most "
            + "any Java EE server and relational database.<br />"
            + "The remote Apache Roller version allows a remote attacker to execute commands on the remote"
            + " system via a OGNL (Object-Graph Navigation Language) expressions.<br /><br />";

    private static final String REMEDY = "Update the remote vulnerable library.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://security.coverity.com/advisory/2013/Oct/remote-code-execution-in-apache-roller-via-ognl-injection.html<br />"
            + "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2013-4212<br />"
            + "https://www.exploit-db.com/exploits/29859/<br /><br />";
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        IHttpRequestResponse baseRequestResponse = webInfo.getHttpRequestResponse();
        // Execute a basic algorithm operation to detect OGNL code execution
        int MAX_RANDOM_INT = 500;
        Random rand = new Random();
        int firstInt = rand.nextInt(MAX_RANDOM_INT);
        int secondInt = rand.nextInt(MAX_RANDOM_INT);
        String multiplication = Integer.toString(firstInt * secondInt);

        String EL_INJECTION_TEST = String.format("${%d*%d}", firstInt, secondInt);
        byte[] GREP_STRING = multiplication.getBytes();

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();


        // Specific test for Apache Roller OGNL RCE CVE-2013-4212.
        if (curURL.getPath().contains("login.rol")) {
            byte[] rawrequest = baseRequestResponse.getRequest();
            List<IParameter> parameters = reqInfo.getParameters();

            //Remove URI parameters
            for (IParameter param : parameters) {
                rawrequest = callbacks.getHelpers().removeParameter(rawrequest, param);
            }

            rawrequest = callbacks.getHelpers().addParameter(rawrequest,
                    callbacks.getHelpers().buildParameter("pageTitle", EL_INJECTION_TEST, IParameter.PARAM_URL)
            );

            // make a request containing our injection test in the insertion point
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), rawrequest);

            byte[] response =  checkRequestResponse.getResponse();
            List<int[]> matches = getMatches(response, GREP_STRING, helpers);


            if (matches.size() > 0) {

                String rceDetails =  String.format("<br /><br />The following algorithm operation has been "
                        + "executed on the remote system:<br /><br /><strong> %d * %d = %s</strong>", firstInt, secondInt, multiplication);

                issues.add(new GtScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        checkRequestResponse,
                        TITLE,
                        DESCRIPTION + rceDetails,
                        REMEDY,
                        Risk.High,
                        Confidence.Tentative
                ));
            }

        }
        webInfo.addIssues(issues);
        return ;
    }

    @Override
    public Set<String> getTags() {
        return new HashSet<>();
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
