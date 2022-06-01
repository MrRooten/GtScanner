package burp.scan.passive;

import burp.*;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class ZabbixRule implements PassiveRule {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if(reqInfo.getUrl().toString().contains("general/zabbix.ico")) {
            IScanIssue issue = new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Zabbix Fingerprint",
                    "This is a Zabbix Service:"+TagTypes.Zabbix_PHP,
                    "",
                    Risk.Information,
                    Confidence.Certain
            );
            callbacks.addScanIssue(issue);
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.Zabbix_PHP);
        }
    }
}
