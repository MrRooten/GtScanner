package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class NginxConfigError implements ModuleBase, RunOnce {
    IHttpRequestResponse CRLFInjection(WebPageInfo webPageInfo) {
        String url = new GtURL(webPageInfo.getUrl()).getBaseUrl();
        if (url.startsWith("https://")) {
            url = url.substring(8);
            url = "http://" + url;
        }

        url = url + "%0d%0aSet-Cookie:%20a=1";
        IHttpService httpService = webPageInfo.getHttpRequestResponse().getHttpService();
        byte[] request = GlobalFunction.helpers.buildHttpRequest(new GtURL(url).getURL());
        IHttpRequestResponse baseRequestResponse = GlobalFunction.callbacks.makeHttpRequest(httpService,request);
        IResponseInfo responseInfo = GlobalFunction.helpers.analyzeResponse(baseRequestResponse.getResponse());
        List<String> headers = responseInfo.getHeaders();
        for (String header : headers) {
            if (header.toLowerCase().startsWith("set-cookie")&&header.contains("a=1")) {
                return baseRequestResponse;
            }
        }
        return null;
    }

    boolean PathTravel(WebPageInfo webPageInfo) {
        return false;
    }

    boolean overWriteAddHeader(WebPageInfo webPageInfo) {
        return false;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        var reqResp = CRLFInjection(webInfo);
        if (reqResp!=null) {
            IScanIssue issue = new GtScanIssue(
                    reqResp.getHttpService(),
                    (new GtURL(webInfo.getUrl())).getURL(),
                    reqResp,
                    "NginxCRLFInjection",
                    "Nginx CRLF Injection",
                    "Remedy",
                    Risk.Medium,
                    Confidence.Firm
            );
            GlobalFunction.callbacks.addScanIssue(issue);

        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.Nginx_Base));
        return tags;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
