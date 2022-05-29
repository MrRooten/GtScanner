package burp.scan.passive;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.scan.lib.HTTPParser;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class PHPMyAdminRule implements PassiveRule{
    private boolean isPHPMyAdmin(String respBody,IResponseInfo respInfo) {
        if (respBody.contains("href=\"phpmyadmin.css.php")) {
            return true;
        }

        String setCookie = HTTPParser.getResponseHeaderValue(respInfo,"set-cookie");
        if (setCookie!=null&&setCookie.contains("phpmyadmin=")) {
            return true;
        }

        return false;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (isPHPMyAdmin(respBody,respInfo)) {
            webPageInfo.addTag(TagTypes.PHPMyAdmin_PHP);
        }
    }
}
