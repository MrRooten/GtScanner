package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;
import burp.IRequestInfo;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.Debug;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.poc.ReversePayloadGenerator;
import burp.scan.lib.utils.BytesUtils;
import burp.scan.lib.utils.Logger;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import org.apache.commons.lang3.tuple.Pair;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

public class SimpleSSRF implements ModuleBase, Debug {
    static final String SSRF_PATTERN = "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    static Pattern pattern = Pattern.compile(SSRF_PATTERN);


    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        var logger = Logger.getLogger(this);
        IRequestInfo reqInfo = webInfo.getReqInfo();
        var parameters = reqInfo.getParameters();
        Map<Pair<Integer,Integer>, IParameter> parametersMap = new HashMap<>();
        for (var parameter : parameters) {
            String value = parameter.getValue();
            value = URLDecoder.decode(value);
            if (pattern.matcher(value).find()) {
                parametersMap.put(Pair.of(parameter.getValueStart(),parameter.getValueEnd()),parameter);
            }
        }

        if (parametersMap.size() == 0) {
            return ;
        }
        Map<String,IParameter> payloadMap = new HashMap<>();
        var generator = new ReversePayloadGenerator();
        var session = GtSession.getGlobalSession();
        for (var range : parametersMap.keySet()) {
            var payload = generator.getReverseUrl();
            var httpPayload = "https://"+payload;
            var newReq = BytesUtils.replaceBytes(webInfo.getRequest(),httpPayload.getBytes(),range.getLeft(),range.getRight());
            var request = new GtRequest(newReq,webInfo.isHttps());
            try {
                var response = session.sendRequest(request);
                payloadMap.put(payload,parametersMap.get(range));

            } catch (IOException e) {
                continue;
            }
        }

        for (var payload : payloadMap.keySet()) {
            var result = generator.getResults(payload);
            if (result.size() != 0) {
                GtScanIssue issue = new GtScanIssue(
                        webInfo.getHttpRequestResponse().getHttpService(),
                        new GtURL(webInfo.getUrl()).getURL(),
                        webInfo.getHttpRequestResponse(),
                        "Simple SSRF",
                        "Vulnable in " + payloadMap.get(payload).getName()+":"+payloadMap.get(payload).getValue(),
                        "",
                        Risk.Medium,
                        Confidence.Certain
                );
                webInfo.addIssue(issue);
                callbacks.addScanIssue(issue);
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
