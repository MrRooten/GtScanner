package burp.scan.active;

import burp.IBurpExtenderCallbacks;
import burp.scan.lib.web.WebPageInfo;

import java.util.Set;

public interface ModuleBase {
    void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo);

    Set<String> getTags();
}
