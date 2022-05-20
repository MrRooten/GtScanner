package burp.scan.issues.impl;

import burp.*;
import burp.scan.issues.IModule;
import burp.scan.lib.web.WebPageInfo;

import java.util.List;

public class MetabaseFileIncludeRule implements IModule {
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, WebPageInfo webInfo) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        IRequestInfo info = helpers.analyzeRequest(baseRequestResponse);

        return null;
    }
}
