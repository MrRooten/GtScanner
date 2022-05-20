package burp.scan.lib.web;

import burp.IHttpRequestResponse;
import burp.scan.passive.CustomScanIssue;
import burp.scan.tags.TagTypes;

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

    public void addTag(TagTypes type) {
        tags.add(type.toString());
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

    public boolean hasTag(TagTypes type) {
        if (tags.contains(type.toString())) {
            return true;
        }
        return false;
    }

    public void setHttpRequestResponse(IHttpRequestResponse iHttpRequestResponse) {
        this.iHttpRequestResponse = iHttpRequestResponse;
    }

    public IHttpRequestResponse getHttpRequestResponse() {
        return iHttpRequestResponse;
    }
}
