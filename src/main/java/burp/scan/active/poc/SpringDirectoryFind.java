package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.utils.Logger;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.*;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class SpringDirectoryFind implements ModuleBase, RunOnce {
    String[] leakInfoDirs = {
            "/v2/api-docs",
            "/swagger-ui.html",
            "/swagger" ,
            "/api-docs" ,
            "/api.html" ,
            "/swagger-ui" ,
            "/swagger/codes" ,
            "/api/index.html" ,
            "/api/v2/api-docs" ,
            "/v2/swagger.json" ,
            "/swagger-ui/html" ,
            "/distv2/index.html" ,
            "/swagger/index.html" ,
            "/sw/swagger-ui.html" ,
            "/api/swagger-ui.html" ,
            "/static/swagger.json" ,
            "/user/swagger-ui.html" ,
            "/swagger-ui/index.html" ,
            "/swagger-dubbo/api-docs" ,
            "/template/swagger-ui.html" ,
            "/swagger/static/index.html" ,
            "/dubbo-provider/distv2/index.html" ,
            "/spring-security-rest/api/swagger-ui.html" ,
            "/spring-security-oauth-resource/swagger-ui.html",
            "/mappings",
            "/metrics",
            "/beans",
            "/configprops",
            "/actuator/metrics",
            "/actuator/mappings",
            "/actuator/beans",
            "/actuator/configprops"
    };

    String[] errorConfigDirs = {
            "/actuator",
                    "/auditevents",
                    "/autoconfig",
                    "/beans",
                    "/caches",
                    "/conditions",
                    "/configprops",
                    "/docs",
                    "/dump",
                    "/env",
                    "/flyway",
                    "/health",
                    "/heapdump",
                    "/httptrace",
                    "/info",
                    "/intergrationgraph",
                    "/jolokia",
                    "/logfile",
                    "/loggers",
                    "/liquibase",
                    "/metrics",
                    "/mappings",
                    "/prometheus",
                    "/refresh",
                    "/scheduledtasks",
                    "/sessions",
                    "/shutdown",
                    "/trace",
                    "/threaddump",
                    "/actuator/auditevents",
                    "/actuator/beans",
                    "/actuator/health",
                    "/actuator/conditions",
                    "/actuator/configprops",
                    "/actuator/env",
                    "/actuator/info",
                    "/actuator/loggers",
                    "/actuator/heapdump",
                    "/actuator/threaddump",
                    "/actuator/metrics",
                    "/actuator/scheduledtasks",
                    "/actuator/httptrace",
                    "/actuator/mappings",
                    "/actuator/jolokia",
                    "/actuator/hystrix.stream"
    };

    GtResponse getErrorPage(String baseUrl) throws IOException {
        GtSession session = new GtSession();
        GtRequest request = new GtRequest(baseUrl + "asdkfjaklsjdfbna");
        var response = session.sendRequest(request);
        return response;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        String baseUrl = new GtURL(webInfo.getUrl()).getBaseUrl();
        GtSession session = new GtSession();
        try {
            var errorPage = getErrorPage(baseUrl);
            for (var leakDir : leakInfoDirs) {
                String targetUrl = baseUrl + leakDir;
                GtRequest request = new GtRequest(targetUrl);
                GtResponse response = session.sendRequest(request);
                if (PageUtils.isPageExistByPage(response,errorPage)) {
                    IScanIssue issue = new GtScanIssue(
                            response.getRequestResponse().getHttpService(),
                            new GtURL(request.getUrl()).getURL(),
                            response.getRequestResponse(),
                            "Spring information leak dir",
                            "Leak dir: " + request.getUrl(),
                            "",
                            Risk.Medium,
                            Confidence.Firm
                    );
                    webInfo.addIssue(issue);
                    callbacks.addScanIssue(issue);
                }
            }

            for (var leakDir : errorConfigDirs) {
                String targetUrl = baseUrl + leakDir;
                GtRequest request = new GtRequest(targetUrl);
                GtResponse response = session.sendRequest(request);
                if (PageUtils.isPageExistByPage(response,errorPage)) {
                    IScanIssue issue = new GtScanIssue(
                            response.getRequestResponse().getHttpService(),
                            new GtURL(request.getUrl()).getURL(),
                            response.getRequestResponse(),
                            "Spring error configuration",
                            "Error configuration: " + request.getUrl(),
                            "",
                            Risk.Medium,
                            Confidence.Firm
                    );
                    webInfo.addIssue(issue);
                    callbacks.addScanIssue(issue);
                }
            }
        } catch (IOException e) {
        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.Spring_Java));
        return tags;
    }
}
