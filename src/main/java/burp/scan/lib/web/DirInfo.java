package burp.scan.lib.web;

import burp.scan.lib.web.utils.GtURL;

public class DirInfo {
    SiteInfo siteInfo;
    String dirUrl;
    public DirInfo(String url) {
        GtURL u = new GtURL(url);
        this.dirUrl = u.getFileDir();
    }
}
