package burp.scan.pre_active;

import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;

public class WeakFileLeak implements PreScanModule{
    static String[] paths = {
            ".git/config",
            "www.zip",
            ".vimrc",
            ".htaccess",
            "robots.txt",
    };
    @Override
    public void scan(WebPageInfo info) {
        var u = new GtURL(info.url);
        var session = GtSession.getGlobalSession();
        for (var path : paths) {
            String targetUrl = u.getBaseUrl() + path;
        }
    }
}
