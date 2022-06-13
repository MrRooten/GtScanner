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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static burp.scan.lib.HTTPMatcher.getMatches;
import static burp.scan.lib.HTTPMatcher.isJavaApplicationByURL;

public class ApacheStrutsDebugMode implements ModuleBase, RunOnce {
    private static final String TITLE = "Apache Struts - Debug Mode - OGNL Console - OGNL Injection";
    private static final String DESCRIPTION = "J2EEscan identified the Development Mode (aka \"devMode\") "
            + "on the remote Apache Struts application."
            + "Web Console through . <br />"
            + "The <i>Debugging Interceptor</i> provides three debugging modes to provide "
            + "insight into the data behind the page. <br />"
            + "The <i>xml mode</i> formats relevant framework objects as an XML document. <br />"
            + "The <b>console mode</b> provides a OGNL command line that accepts entry of runtime expressions. "
            + "<b>This could lead to RCE</b><br /> "
            + "The <i>browser mode</i> adds an interactive page that display objects from the Value Stack. <br /><br />"
            + "<b>References</b>:<br />"
            + "https://struts.apache.org/docs/debugging.html<br />"
            + "https://struts.apache.org/docs/devmode.html<br />"
            + "http://www.pwntester.com/blog/2014/01/21/struts-2-devmode-an-ognl-backdoor/";

    private static final String REMEDY = "Modify the <i>struts.devMode</i> property on the production server";

    private static final byte[] GREP_STRING = "'OGNL Console'".getBytes();

    private PrintWriter stderr;

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        IHttpRequestResponse baseRequestResponse = webInfo.getHttpRequestResponse();
        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL url = reqInfo.getUrl();

        if (!isJavaApplicationByURL(url)) {
            webInfo.addIssues(issues);
            return ;
        }

        byte[] rawrequest = baseRequestResponse.getRequest();
        List<IParameter> parameters = reqInfo.getParameters();

        //Remove URI parameters
        for (IParameter param : parameters) {
            rawrequest = callbacks.getHelpers().removeParameter(rawrequest, param);
        }

        rawrequest = callbacks.getHelpers().addParameter(rawrequest,
                callbacks.getHelpers().buildParameter("debug", "console", IParameter.PARAM_URL)
        );

        // make a request containing our injection test in the insertion point
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), rawrequest);

        byte[] response = checkRequestResponse.getResponse();
        List<int[]> matches = getMatches(response, GREP_STRING, helpers);

        if (matches.size() > 0) {

            issues.add(new GtScanIssue(
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
