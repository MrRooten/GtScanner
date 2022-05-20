package burp.scan.lib.web;

import burp.scan.tags.Tag;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class SiteInfo {
    String host;
    Set<Tag> tags = new HashSet<>();
    public SiteInfo(String host) {
        this.host = host;
    }

    static HashMap<String,SiteInfo> globalSitesInfo = new HashMap<>();
    static SiteInfo getSiteInfo(String url) {
        String host = null;
        try {
            URL _u = new URL(url);
            host = _u.getHost();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        if (host == null) {
            return null;
        }

        if (globalSitesInfo.containsKey(host)) {
            globalSitesInfo.put(host,new SiteInfo(host));
        }

        SiteInfo info = globalSitesInfo.get(host);

        return info;
    }
}
