package burp.scan.issues.impl;

import burp.*;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.Confidence;
import burp.scan.issues.IModule;
import burp.scan.lib.Risk;

import java.net.URL;
import java.util.*;

import static burp.scan.lib.HTTPMatcher.getMatches;
import static burp.scan.lib.HTTPMatcher.isJavaApplicationByURL;


public class EL3Injection  implements IModule {

    private static final String TITLE = "EL 3.0/Lambda Injection";
    private static final String DESCRIPTION = "J2EEscan identified an EL 3.0 (Expression Language) "
            + "Injection vulnerability; an expression language makes it possible to easily "
            + "access application data stored in JavaBeans components and execute code on the server."  
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://sectooladdict.blogspot.co.il/2014/12/el-30-injection-java-is-getting-hacker.html<br />"
            + "http://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf<br />"
            + "https://jcp.org/en/jsr/detail?id=341<br />"; 
            
    private static final String REMEDY = "Do not use untrusted user input directly in lambda EL3 statements";

    private static final byte[] GREP_STRING = "java.vendor".getBytes();  
    private static final List<byte[]> EL_INJECTION_TESTS = Arrays.asList(
            "System.getProperties()".getBytes()
    );            
     
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebPageInfo webInfo) {
      
        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();
        
        
         // Skip test for not j2ee applications
        if (!isJavaApplicationByURL(curURL)){
            return issues;
        }

              
        for (byte[] INJ_TEST : EL_INJECTION_TESTS) {
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);


            // look for matches of our active check grep string
            List<int[]> matches = getMatches(checkRequestResponse.getResponse(), GREP_STRING, helpers);
            if (matches.size() > 0) {

                issues.add(new RequestsInfo.CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        checkRequestResponse,
                        TITLE,
                        DESCRIPTION,
                        REMEDY,
                        Risk.High,
                        Confidence.Tentative
                ));
            }
            
        }    
          
        return issues;
    }
}
