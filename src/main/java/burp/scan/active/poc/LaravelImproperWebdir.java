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
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class LaravelImproperWebdir implements ModuleBase, RunOnce, Debug {

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        GtSession session = GtSession.getGlobalSession();
        GtURL url = new GtURL(webInfo.getUrl());
        String targetUrl = url.getBaseUrl() + "/storage/logs/laravel.log";
        GtRequest request = new GtRequest(targetUrl);
        Logger logger = Logger.getLogger(this);
        try {
            var response = session.sendRequest(request);
            var body = response.getBody();
            var respBody = new String(body);
            var respContentType = response.getHeaderValue("Content-type");
            if (response.getStatudCode() == 200 && (respContentType.contains("plain") ||
                    respContentType.contains("octet-stream")) && (respBody.contains("vendor\\laravel\\framework")
            ||respBody.contains("vendor/laravel/framework")) && (respBody.contains("stacktrace") || respBody.contains("Stack trace"))) {
                IScanIssue issue = new GtScanIssue(
                        response.getRequestResponse().getHttpService(),
                        url.getURL(),
                        response.getRequestResponse(),
                        "Laravel Improper Webdir",
                        "https://github.com/dem0ns/improper",
                        "",
                        Risk.Medium,
                        Confidence.Firm
                );
                webInfo.addIssue(issue);
                callbacks.addScanIssue(issue);
            }
        } catch (IOException e) {
            logger.error(e.getLocalizedMessage());
        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> res = new HashSet<>();
        res.add(TagUtils.toStandardName(TagTypes.Laravel_PHP));
        return res;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
