package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

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
        List<String> headers = new ArrayList<>();
        headers.add("GET " + "/" + " HTTP/1.1");
        headers.add("Host: " + "www.baidu.com");
        headers.add("Content-Type: application/x-www-form-urlencoded");
        headers.add("Cookie: JSESSIONID=4416F53DDE1DBC8081CDBDCDD1666FB0");

        String body = "actionOutcome=/success.xhtml?user%3d%23{expressions.getClass().forName('java.lang.Runtime').getDeclaredMethod('getRuntime')}";

        byte[] seamMesssage = new byte[0];
        try {
            seamMesssage = callbacks.getHelpers().buildHttpRequest(new URL("https://www.baidu.com"));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        callbacks.printOutput(new String(seamMesssage));
        IHttpService httpService = callbacks.getHelpers().buildHttpService("www.baidu.com",443,true);
        IHttpRequestResponse res = callbacks.makeHttpRequest(httpService,seamMesssage);
        byte[] bytes = res.getResponse();
        if (bytes == null) {
            return ;
        }
        callbacks.printOutput(new String(bytes));
    }
}
