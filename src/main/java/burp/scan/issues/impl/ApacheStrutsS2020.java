package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.Confidence;
import burp.scan.issues.IModule;
import burp.scan.lib.Risk;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.scan.lib.HTTPMatcher.isJavaApplicationByURL;


public class ApacheStrutsS2020 implements IModule {

    private static final String TITLE = "Apache Struts S2-020 ClassLoader Manipulation";
    private static final String DESCRIPTION = "J2EEscan identified a ClassLoader Manipulation;"
            + "Apache Struts 2 <i>ParametersInterceptor</i> allows "
            + "access to '<i>class</i>' parameter which is directly mapped to <i>getClass()</i>"
            + " method and allows ClassLoader manipulation.<br />"
            + "A remote user could be able to manipulate the servlet container's classloader to execute"
            + "arbitrary commands on the remote system.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/release/2.3.x/docs/s2-020.html<br />"
            + "http://struts.apache.org/release/2.3.x/docs/s2-021.html<br />"
            + "http://struts.apache.org/release/2.3.x/docs/version-notes-23161.html<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0094<br />"
            + "http://drops.wooyun.org/papers/1377<br />"
            + "http://sec.baidu.com/index.php?research/detail/id/18<br />"
            + "http://www.pwntester.com/blog/2014/04/24/struts2-0day-in-the-wild/<br />";
    private static final String REMEDY = "Update the remote Struts vulnerable library";

    // Check for specific patterns on response page
    private static final Pattern CLASSLOADER_PM = Pattern.compile("Invalid field value for field|No result defined for action",
            Pattern.DOTALL | Pattern.MULTILINE);

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebPageInfo webInfo) {

        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        List<IParameter> parameters = reqInfo.getParameters();

        URL curURL = reqInfo.getUrl();

        byte[] modifiedRawRequest = null;
        List<IScanIssue> issues = new ArrayList<>();

        if (!isJavaApplicationByURL(curURL)) {
            return issues;
        }

        byte[] rawrequest = baseRequestResponse.getRequest();
        //Remove URI parameters
        for (IParameter param : parameters) {
            rawrequest = callbacks.getHelpers().removeParameter(rawrequest, param);
        }

        // Dynamic random string for URL classloader
        long unixTime = System.currentTimeMillis() / 1000L;
        String classLoaderStringTest = "testClassloaderManipulation" + unixTime;

        /**
         * Make a request containing our injection test in the insertion point
         *
         * Original fix for this vulnerability was to to forbid the
         * (.*\.|^)class\..* regex
         * https://github.com/apache/struts/commit/aaf5a3010e3c11ae14e3d3c966a53ebab67146be
         *
         * It was possible to bypass this "protection" using "Class.classloader"
         * (capital 'C').
         *
         * This payload covers also Apache Struts S2-021 advisory, caused by a
         * wrong patch attempt.
         */
        modifiedRawRequest = callbacks.getHelpers().addParameter(rawrequest,
                callbacks.getHelpers().buildParameter("Class.classLoader.URLs[0]",
                        classLoaderStringTest, IParameter.PARAM_URL)
        );

        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), modifiedRawRequest);

        // Get the response body
        byte[] responseBytes = checkRequestResponse.getResponse();
        String response = helpers.bytesToString(responseBytes);

        Matcher matcher = CLASSLOADER_PM.matcher(response);

        if (matcher.find()) {
            issues.add(new RequestsInfo.CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    checkRequestResponse,
                    TITLE,
                    DESCRIPTION,
                    REMEDY,
                    Risk.High,
                    Confidence.Certain
            ));
        }

        return issues;
    }
}
