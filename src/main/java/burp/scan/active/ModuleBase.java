package burp.scan.active;

import burp.IBurpExtenderCallbacks;
import burp.scan.lib.web.WebPageInfo;

public interface ModuleBase {
    void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo);
}
