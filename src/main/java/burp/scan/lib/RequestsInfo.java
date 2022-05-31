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

    public static class CustomScanIssue implements IScanIssue {

        private IHttpService httpService;
        private URL url;
        private IHttpRequestResponse httpMessages;
        private String name;
        private String detail;
        private Risk severity;
        private String remedy;
        private Confidence confidence = Confidence.Certain;

        public CustomScanIssue(
                IHttpService httpService,
                URL url,
                IHttpRequestResponse httpMessages,
                String name,
                String detail,
                String remedy,
                Risk severity,
                Confidence confidence) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = "GtScan - " + name;
            this.detail = detail;
            this.remedy = remedy;
            this.severity = severity;
            this.confidence = confidence;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return name;
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            return severity.toString();
        }

        @Override
        // "Certain", "Firm" or "Tentative"
        public String getConfidence() {
            return confidence.toString();
        }

        @Override
        public String getIssueBackground() {
            return null;
        }

        @Override
        public String getRemediationBackground() {
            return null;
        }

        @Override
        public String getIssueDetail() {
            return detail;
        }

        @Override
        public String getRemediationDetail() {
            return remedy;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return new IHttpRequestResponse[]{httpMessages};
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }

    }
}
