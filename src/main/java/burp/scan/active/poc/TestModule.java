package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.RequestParser;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;

import java.util.HashMap;
import java.util.Set;

public class TestModule implements ModuleBase, RunOnce {
    ModuleMeta meta;
    static {
        HashMap<String,Object> info = new HashMap<>();
        info.put("author","UnknownMan");
        info.put("relateVB",new String[]{"CVE-xxxx-xxxxx"});
        info.put("level", Risk.High);
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        IRequestInfo info = callbacks.getHelpers().analyzeRequest(webInfo.getHttpRequestResponse());
        RequestParser parser = new RequestParser(info);
        var parameters = parser.getParameters();
        for (var parameter : parameters) {
            callbacks.printOutput(parameter.getName()+": "+parameter.getValue());
        }
    }

    @Override
    public Set<String> getTags() {
        return null;
    }
}
