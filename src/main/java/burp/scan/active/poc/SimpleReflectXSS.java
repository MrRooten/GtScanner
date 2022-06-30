package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.utils.BytesUtils;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class SimpleReflectXSS implements ModuleBase {
    static String payload = "<script>1</script>";

    boolean isMatch(String resp) {
        if (resp.contains(payload)) {
            return true;
        }
        return false;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        IRequestInfo reqInfo = webInfo.getReqInfo();
        var parameters = reqInfo.getParameters();
        List<IParameter> xssParameters = new ArrayList<>();
        for (var parameter : parameters) {
            var value = parameter.getValue();
            if (webInfo.getReqBody().contains(value) && parameter.getType() == IParameter.PARAM_URL) {
                xssParameters.add(parameter);
            }
        }

        var bytes = webInfo.getResponse();
        GtSession session = new GtSession();
        boolean isHttps = new GtURL(webInfo.getUrl()).isHttps();
        for (var xssParameter : xssParameters) {
            var targetBytes = BytesUtils.replaceBytes(bytes,payload.getBytes(),xssParameter.getValueStart(),xssParameter.getValueEnd());
            GtRequest request = new GtRequest(targetBytes,isHttps);
            try {
                var resp = session.sendRequest(request);
                if (isMatch(new String(resp.getBody()))) {
                    IScanIssue issue = new GtScanIssue(
                            resp.getRequestResponse().getHttpService(),
                            new GtURL(request.getUrl()).getURL(),
                            resp.getRequestResponse(),
                            "Simple Reflect XSS",
                            "There is a xss in url:(" + xssParameter.getName() + ":" + xssParameter.getValue()+")",
                            "",
                            Risk.Medium,
                            Confidence.Certain
                    );
                    webInfo.addIssue(issue);
                    callbacks.addScanIssue(issue);
                }
            } catch (IOException e) {
                e.printStackTrace();
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
