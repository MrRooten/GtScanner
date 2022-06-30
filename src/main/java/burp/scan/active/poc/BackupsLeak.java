package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.Debug;
import burp.scan.active.feature.Disable;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.lib.web.utils.PageUtils;
import burp.scan.lib.Confidence;


import java.io.IOException;
import java.util.*;


public class BackupsLeak implements ModuleBase, Debug {
    static String[] FILES = {
            ".git/config",
            ".svn/entries",
            ".DS_Store",
            "database.inc",
            "common.inc",
            "db.inc",
            "connect.inc",
            "conn.inc",
            "sql.inc",
            "debug.inc",
            "www.zip"
    };

    static Map<String, String[]> filesMatches = new HashMap<>();
    static Set<String> urls = new HashSet<>();
    static {
        filesMatches.put(".git/config",new String[]{"[core]","master","main"});
    }

    boolean isFileMatch(String file,String content) {
        String[] matches = filesMatches.get(file);
        if (matches == null) {
            return false;
        }
        for (var match : matches) {
            if (content.contains(match)) {
                return true;
            }
        }

        return false;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        String url = webInfo.getUrl();
        callbacks.printOutput("URL:"+webInfo.url);
        GtURL u = new GtURL(url);
        String baseUrl = u.getFileDir();
        if (urls.contains(baseUrl)) {
            return ;
        } else {
            urls.add(baseUrl);
        }
        IHttpService httpService = webInfo.getHttpRequestResponse().getHttpService();
        for (String FILE : FILES) {
            String targetUrl = baseUrl + FILE;
            callbacks.printOutput("target url:"+targetUrl);
            try {
                GtSession request = GtSession.getGlobalSession();
                GtRequest req = new GtRequest(targetUrl);
                var result = request.sendRequest(req);
                var content = new String(result.getBody());
                if (isFileMatch(FILE,content)) {
                    IScanIssue issue = new GtScanIssue(
                            httpService,
                            u.getURL(),
                            result.getRequestResponse(),
                            "BackupsLeak",
                            "BackupFile:"+FILE,
                            "",
                            Risk.Medium,
                            Confidence.Certain
                    );
                    callbacks.addScanIssue(issue);
                    webInfo.addIssue(issue);
                    continue;
                }
                if(PageUtils.isPageExist(targetUrl)) {
                    IScanIssue issue = new GtScanIssue(
                            httpService,
                            u.getURL(),
                            webInfo.getHttpRequestResponse(),
                            "BackupsLeak",
                            "BackupFile:"+FILE,
                            "",
                            Risk.Medium,
                            Confidence.Tentative
                    );
                    callbacks.addScanIssue(issue);
                }
            } catch (IOException e) {

            }
        }
    }

    @Override
    public Set<String> getTags() {
        return null;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
