package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.GlobalFunction;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.passive.Confidence;
import burp.scan.passive.CustomScanIssue;

import java.util.List;

public class NginxConfigError implements ModuleBase, RunOnce {
    boolean CRLFInjection(WebPageInfo webPageInfo) {
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
            if (header.contains("a=1")) {
                return true;
            }
        }
        return false;
    }

    boolean PathTravel(WebPageInfo webPageInfo) {
        return false;
    }

    boolean overWriteAddHeader(WebPageInfo webPageInfo) {
        return false;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        if (CRLFInjection(webInfo)) {
            IScanIssue issue = new CustomScanIssue(
                    webInfo.getHttpRequestResponse().getHttpService(),
                    (new GtURL(webInfo.getUrl())).getURL(),
                    webInfo.getHttpRequestResponse(),
                    "NginxCRLFInjection",
                    "Nginx CRLF Injection",
                    "Remedy",
                    Risk.High,
                    Confidence.Firm
            );
            GlobalFunction.callbacks.addScanIssue(issue);

        }
    }
}
