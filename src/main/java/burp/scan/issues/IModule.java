package burp.scan.issues;


import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.scan.lib.WebInfo;
import burp.scan.tags.Tag;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public interface IModule {
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks,
                                 IHttpRequestResponse baseRequestResponse,
                                 IScannerInsertionPoint insertionPoint, WebInfo webInfo);
}