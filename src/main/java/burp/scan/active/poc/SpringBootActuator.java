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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.getApplicationContext;
import static burp.scan.lib.HTTPMatcher.getMatches;

public class SpringBootActuator implements ModuleBase, RunOnce {
    private static final String TITLE = "Spring Boot Actuator";
    private static final String DESCRIPTION = "J2EEscan identified the Spring Boot Actuator endpoint. <br />"
            + "This development console allows to access remote sensitive information (ex: enviroment variables, http sessions).<br /><br/>"
            + "The endpoints could be:<br >"
            + "<ul>"
            + "<li>autoconfig</li>"
            + "<li>beans</li>"
            + "<li>configprops</li>"
            + "<li>dump</li>"
            + "<li>env</li>"
            + "<li>health</li>"
            + "<li>info</li>"
            + "<li>metrics</li>"
            + "<li>mappings</li>"
            + "<li>shutdown</li>"
            + "<li>trace</li>"
            + "<li>refresh (Spring Cloud)</li>"
            + "<li>jolokia</li>"
            + "</ul>"
            + "<br /><b>References</b><br />"
            + "http://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#production-ready-endpoints<br />"
            + "https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-jmx.html<br />";
    private static final String REMEDY = "Evaluate the availability of the configured endpoint and its risk. Disable or restrict access to this endpointon on the production server";

    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "{\"status\":\"UP\"}".getBytes(),
            "{\"_links\":".getBytes(),
            "org.spring".getBytes(),
            "java.vendor".getBytes()
    );


    private static final List<String> SPRINGBOOT_ACTUATOR_PATHS = Arrays.asList(
            "/health",
            "/manager/health",
            "/actuator",
            "/actuator/jolokia/list",
            "/jolokia/list",
            "/env"
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

            for (String springboot_path : SPRINGBOOT_ACTUATOR_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), springboot_path);
                    byte[] webconsoleRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our Spring Boot endpoint
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), webconsoleRequest);

                    byte[] requestResponse = checkRequestResponse.getResponse();

                    // look for matches of our active check grep string
                    for (byte[] GREP_STRING : GREP_STRINGS) {

                        List<int[]> matches = getMatches(requestResponse, GREP_STRING, helpers);
                        if (matches.size() > 0) {

                            callbacks.addScanIssue(new GtScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
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
         * Ex: http://www.example.com/myapp/manage/env
         */
        String context = getApplicationContext(url);

        if (context.isEmpty()) {
            webInfo.addIssues(issues);
            return ;
        }

        String contextURI = system + context;

        if (!hsc.contains(contextURI)) {

            hsc.add(contextURI);

            for (String webconsole_path : SPRINGBOOT_ACTUATOR_PATHS) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), context + webconsole_path);
                    byte[] webconsoleRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our Spring Boot endpoint
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), webconsoleRequest);

                    byte[] requestResponse = checkRequestResponse.getResponse();


                    // look for matches of our active check grep string
                    for (byte[] GREP_STRING : GREP_STRINGS) {

                        List<int[]> matches = getMatches(requestResponse, GREP_STRING, helpers);
                        if (matches.size() > 0) {

                            callbacks.addScanIssue(new GtScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
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
        tags.add(TagUtils.toStandardName(TagTypes.SpringBoot_Spring));
        return tags;
    }
}
