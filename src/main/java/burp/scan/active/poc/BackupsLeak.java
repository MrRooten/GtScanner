package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.Debug;
import burp.scan.active.feature.Disable;
import burp.scan.lib.CustomScanIssue;
import burp.scan.lib.RequestsInfo;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.lib.web.utils.PageUtils;
import burp.scan.lib.Confidence;


import java.io.IOException;
import java.util.*;


public class BackupsLeak implements ModuleBase, Debug, Disable {
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
            "debug.inc"
    };

    static Map<String, String[]> filesMatches = new HashMap<>();
    static Set<String> urls = new HashSet<>();
    static {
        filesMatches.put(".git/config",new String[]{"[core]","master","main"});
        filesMatches.put(".svn/entries",null);
        filesMatches.put(".DS_Store",null);
        filesMatches.put("database.inc",null);
        filesMatches.put("common.inc",null);
        filesMatches.put("db.inc",null);
        filesMatches.put("connect.inc",null);
        filesMatches.put("sql.inc",null);
        filesMatches.put("debug.inc",null);
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
        for (String FILE : filesMatches.keySet()) {
            String targetUrl = baseUrl + FILE;
            callbacks.printOutput("target url:"+targetUrl);
            try {
                GtRequest request = new GtRequest();
                var result = request.burpGet(targetUrl);
                var content = new String(result.getResponse());
                if (isFileMatch(FILE,content)) {
                    IScanIssue issue = new CustomScanIssue(
                            httpService,
                            u.getURL(),
                            result,
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
                    IScanIssue issue = new CustomScanIssue(
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
}
