package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class ApacheFlinkRule implements PassiveRule {

    Confidence levelApacheFlink(String respBody) {
        if (respBody.contains("<title>Apache Flink Web Dashboard</title>")) {
            return Confidence.Certain;
        }

        if (respBody.contains("<img alt=\"apache flink dashboard\" src=\"images/flink-logo.png")) {
            return Confidence.Certain;
        }

        return null;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        var level = levelApacheFlink(respBody);
        if (level != null) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Apache Flink Fingerprint",
                    "May have CVE-2020-17518,CVE-2020-17519",
                    "",
                    Risk.Information,
                    level
            );
            callbacks.addScanIssue(issue);
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.ApacheFlink_Java);
        }
    }
}
