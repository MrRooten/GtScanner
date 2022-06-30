package burp.scan.lib.web.utils;

import me.xdrop.fuzzywuzzy.FuzzySearch;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class PageUtils {
    static int getSimilarity(byte[] b1,byte[] b2) {
        return 1;
    }

    static Set<String> Urls = new HashSet<>();
    static HashMap<String,byte[]> dirErrorPageMap = new HashMap<>();
    static byte[] getErrorPage(String url) throws IOException {
        String baseUrl = new GtURL(url).getFileDir();
        if (dirErrorPageMap.containsKey(baseUrl)) {
            return dirErrorPageMap.get(baseUrl);
        }
        GtSession request = new GtSession();
        var response = request.get(baseUrl+"abvjashdfabvjaskdfjkhsdfj");
        dirErrorPageMap.put(baseUrl,response.getBody());
        if (response.getBody() == null) {
            byte[] tmp = new byte[0];
            return tmp;
        }
        return response.getBody();
    }
    public static boolean isPageExist(String url) throws IOException {
        GtSession request = new GtSession();
        var response = request.get(url);
        if (response.getStatusCode() == 404) {
            return false;
        }
        byte[] errorPage = getErrorPage(url);


        if (FuzzySearch.ratio(new String(response.getBody()),new String(errorPage)) > 95) {
            return false;
        }
        return true;
    }

    public static int getDifferRatio(String page1,String page2) {
        return FuzzySearch.ratio(page1,page2);
    }

    public static boolean isPageExistByPage(GtResponse page,GtResponse errorPage) throws IOException {
        if (errorPage.getStatusCode() == 404) {
            if (page.getStatusCode() != 404) {
                return false;
            } else {
                return true;
            }
        }

        String sPage = new String(page.getBody());
        String sErrorPage = new String(errorPage.getBody());
        if (getDifferRatio(sPage,sErrorPage) > 95) {
            return false;
        }

        return true;
    }
}
