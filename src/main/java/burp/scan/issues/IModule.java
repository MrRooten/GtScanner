package burp.scan.issues;


import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.scan.lib.web.WebPageInfo;

import java.util.List;

public interface IModule {
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks,
                                 IHttpRequestResponse baseRequestResponse,
                                 IScannerInsertionPoint insertionPoint, WebPageInfo webInfo);
}