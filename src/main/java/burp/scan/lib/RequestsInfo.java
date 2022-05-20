package burp.scan.lib;

import burp.IRequestInfo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class RequestsInfo {
    HashMap<IRequestInfo, List<WebInfo>> infoTable = new HashMap<>();

    public static RequestsInfo singleRequestInfo = null;
    public static RequestsInfo getInstance() {
        if (RequestsInfo.singleRequestInfo == null) {
            RequestsInfo.singleRequestInfo = new RequestsInfo();
        }

        return RequestsInfo.singleRequestInfo;
    }

    public void putInfo(IRequestInfo request,WebInfo info) {
        if (!infoTable.containsKey(request)) {
            infoTable.put(request, new ArrayList<WebInfo>());
        }

        infoTable.get(request).add(info);
    }

    public List<WebInfo> getInfo(IRequestInfo request) {
        return infoTable.get(request);
    }
}
