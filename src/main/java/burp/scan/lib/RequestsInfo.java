package burp.scan.lib;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.scan.lib.web.WebPageInfo;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class RequestsInfo {
    HashMap<IRequestInfo, List<WebPageInfo>> infoTable = new HashMap<>();

    public static RequestsInfo singleRequestInfo = null;
    public static RequestsInfo getInstance() {
        if (RequestsInfo.singleRequestInfo == null) {
            RequestsInfo.singleRequestInfo = new RequestsInfo();
        }

        return RequestsInfo.singleRequestInfo;
    }

    public void putInfo(IRequestInfo request, WebPageInfo info) {
        if (!infoTable.containsKey(request)) {
            infoTable.put(request, new ArrayList<WebPageInfo>());
        }

        infoTable.get(request).add(info);
    }

    public List<WebPageInfo> getInfo(IRequestInfo request) {
        return infoTable.get(request);
    }


}
