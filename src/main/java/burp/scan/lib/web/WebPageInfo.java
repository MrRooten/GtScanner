package burp.scan.lib.web;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.scan.lib.GlobalFunction;
import burp.scan.lib.RequestInfoParser;
import burp.scan.lib.utils.Config;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.util.*;

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
    private List<IScanIssue> issues = new ArrayList<>();
    private IHttpRequestResponse iHttpRequestResponse;
    private SiteInfo siteInfo;
    private Map<Class,Object> passiveInfo = new HashMap<>();
    private RequestInfoParser parser;
    private String reqBody;
    private String respBody;
    private IRequestInfo reqInfo;
    private IResponseInfo respInfo;

    private boolean isHttps = false;

    private Config config = new Config();
    public void addTag(TagTypes type) {
        String typeString = TagUtils.toStandardName(type);
        tags.add(typeString);
        this.siteInfo.addTag(type);
    }

    public WebPageInfo(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo requestInfo = GlobalFunction.helpers.analyzeRequest(baseRequestResponse);
        this.siteInfo = SiteInfo.getSiteInfo(requestInfo.getUrl().toString());
        this.request = baseRequestResponse.getRequest();
        this.response = baseRequestResponse.getResponse();
        this.iHttpRequestResponse = baseRequestResponse;
        this.url = requestInfo.getUrl().toString();
        this.parser = new RequestInfoParser(GlobalFunction.helpers.analyzeRequest(this.request));
    }

    public WebPageInfo(IHttpRequestResponse baseRequestResponse,String reqBody,String respBody,IRequestInfo reqInfo,IResponseInfo respInfo) {
        IRequestInfo requestInfo = GlobalFunction.helpers.analyzeRequest(baseRequestResponse);
        this.siteInfo = SiteInfo.getSiteInfo(requestInfo.getUrl().toString());
        this.request = baseRequestResponse.getRequest();
        this.response = baseRequestResponse.getResponse();
        this.iHttpRequestResponse = baseRequestResponse;
        this.url = requestInfo.getUrl().toString();
        this.parser = new RequestInfoParser(GlobalFunction.helpers.analyzeRequest(this.request));
        this.reqBody = reqBody;
        this.respBody = respBody;
        this.reqInfo = reqInfo;
        this.respInfo = respInfo;
    }
    public String getReqBody() {
        return this.reqBody;
    }

    public void setConfig(Config config) {
        this.config.initialize(config.toJsonString());
    }
    public String getRespBody() {
        return this.respBody;
    }

    public IRequestInfo getReqInfo() {
        return this.reqInfo;
    }

    public IResponseInfo getRespInfo() {
        return this.respInfo;
    }

    public RequestInfoParser getParser() {
        return this.parser;
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }

    public void addIssue(IScanIssue issue) {
        this.issues.add(issue);
    }

    public void addIssues(List<IScanIssue> issues) {
        this.issues.addAll(issues);
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

    public List<IScanIssue> getIssues() {
        return this.issues;
    }

    public void setIsHttps(boolean isHttps) {
        this.isHttps = isHttps;
    }
    public boolean isHttps() {
        return this.isHttps;
    }
}
