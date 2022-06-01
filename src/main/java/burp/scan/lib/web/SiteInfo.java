package burp.scan.lib.web;

import burp.IExtensionHelpers;
import burp.scan.active.ModuleBase;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class SiteInfo {
    String host;
    Set<String> tags = new HashSet<>();
    Set<String> alreadyRuns = new HashSet<>();
    WebPageInfo errorPage;
    IExtensionHelpers helpers;
    public SiteInfo(String host) {
        this.host = host;
    }

    public void addTags(WebPageInfo webPageInfo) {
        this.tags.addAll(webPageInfo.tags);
    }

    public void addTag(TagTypes tag) {
        String tagString = TagUtils.toStandardName(tag);
        tags.add(tagString);
    }

    public Set<String> getTags() {
        return this.tags;
    }
    public Set<String> getAllTags() {
        Set<String> allTags = new HashSet<>();
        for (String curTag : this.tags) {
            if (curTag.equals("Base")) {
                continue;
            }
            allTags.addAll(TagUtils.GetTag(curTag).GetAncestors());
        }
        allTags.addAll(this.tags);
        return allTags;
    }
    public boolean hasTag(TagTypes tag) {
        String tagString = tag.toString().split("_")[0];

        Set<String> allTags = new HashSet<>();
        for (String curTag : this.tags) {
            allTags.addAll(TagUtils.GetTag(curTag).GetAncestors());
        }

        if (allTags.contains(tagString)) {
            return true;
        }
        return false;
    }

    public boolean hasTags(Set<String> tags) {
        return this.tags.containsAll(tags);
    }
    public String getHost() {
        return this.host;
    }

    public void addRunnedModule(ModuleBase module) {
        this.alreadyRuns.add(module.getClass().toString());
    }

    public boolean containsRunnedModule(ModuleBase module) {
        return this.alreadyRuns.contains(module.getClass().toString());
    }

    public void setErrorPage(WebPageInfo pageInfo) {

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

        if (!globalSitesInfo.containsKey(host)) {
            SiteInfo siteInfo = new SiteInfo(host);
            globalSitesInfo.put(host,new SiteInfo(host));
        }

        SiteInfo info = globalSitesInfo.get(host);

        return info;
    }


}
