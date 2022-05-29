package burp.scan.lib.web;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.scan.lib.GlobalFunction;
import burp.scan.passive.CustomScanIssue;
import burp.scan.tags.TagTypes;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/*
* This Class is for saving passive module result
* */
public class WebPageInfo {
    public Set<String> tags = new HashSet<>();
    public Class scanModule = null;
    public String url = null;
    public Object extendInfo = null;
    private byte[] request;
    private byte[] response;
    private List<CustomScanIssue> issues = new ArrayList<>();
    private IHttpRequestResponse iHttpRequestResponse;
    private SiteInfo siteInfo;
    public WebPageInfo(String url) {
        this.siteInfo = SiteInfo.getSiteInfo(url);
    }
    public void addTag(TagTypes type) {
        tags.add(type.toString());
        this.siteInfo.addTag(type);
    }

    public WebPageInfo(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo requestInfo = GlobalFunction.helpers.analyzeRequest(baseRequestResponse);
        this.siteInfo = SiteInfo.getSiteInfo(requestInfo.getUrl().toString());
        this.request = baseRequestResponse.getRequest();
        this.response = baseRequestResponse.getResponse();
    }
    public void setRequest(byte[] request) {
        this.request = request;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }

    public void addIssue(CustomScanIssue issue) {
        this.issues.add(issue);
    }

    public byte[] getRequest() {
        return request;
    }

    public byte[] getResponse() {
        return response;
    }

    public String getUrl() {
        return this.url;
    }

    public boolean hasTag(TagTypes type) {
        if (tags.contains(type.toString())) {
            return true;
        }
        return false;
    }

    public void setHttpRequestResponse(IHttpRequestResponse iHttpRequestResponse) {
        this.iHttpRequestResponse = iHttpRequestResponse;
    }

    public SiteInfo getSiteInfo() {
        return this.siteInfo;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public IHttpRequestResponse getHttpRequestResponse() {
        return iHttpRequestResponse;
    }

    public boolean isPageExist() {
        return false;
    }
}
