package burp.scan.active;

import burp.IBurpExtenderCallbacks;
import burp.scan.lib.WebInfo;

public interface ModuleBase {
    void scan(IBurpExtenderCallbacks callbacks, WebInfo webInfo);
}
