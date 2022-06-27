package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.scan.active.ModuleBase;
import burp.scan.lib.web.WebPageInfo;

import java.util.Set;

public class SimpleXXE implements ModuleBase {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {

    }

    @Override
    public Set<String> getTags() {
        return null;
    }
}
