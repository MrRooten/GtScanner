package burp.scan.pre_active;

import burp.scan.lib.fingerprinthub.FingerPrint;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;
import burp.scan.lib.web.utils.GtURL;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

public class FaviconIconModule implements PreScanModule{
    @Override
    public void scan(WebPageInfo info) {
        var url = new GtURL(info.getUrl());
        GtRequest request = new GtRequest(info.getRequest(),url.isHttps());
        request.setQueryPath("/favicon.icon");
        var session = GtSession.getGlobalSession();
        try {
            var response = session.sendRequest(request);
            var body = response.getBody();
            var md = MessageDigest.getInstance("md5");
            var digest = md.digest(body);
            BigInteger bigInt = new BigInteger(1,digest);
            String hashText = bigInt.toString(16).toLowerCase();
            var finger = FingerPrint.faviconHash.get(hashText);
            if (finger == null) {
                return ;
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
