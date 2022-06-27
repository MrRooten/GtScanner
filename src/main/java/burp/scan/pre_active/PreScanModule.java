package burp.scan.pre_active;

import burp.scan.lib.web.WebPageInfo;

public interface PreScanModule {
    public void scan(WebPageInfo info);
}
