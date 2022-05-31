package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.scan.active.ModuleBase;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

import java.util.HashSet;
import java.util.Set;

public class ApachePathTravel implements ModuleBase {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {

    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagTypes.ApacheHttp_Base.toString());
        return tags;
    }
}
