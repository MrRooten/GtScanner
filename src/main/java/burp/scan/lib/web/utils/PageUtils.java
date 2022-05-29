package burp.scan.lib.web.utils;

import burp.IExtensionHelpers;
import burp.IResponseInfo;
import burp.scan.lib.GlobalFunction;
import burp.scan.lib.web.WebPageInfo;
import me.xdrop.fuzzywuzzy.FuzzySearch;
import me.xdrop.fuzzywuzzy.ratios.SimpleRatio;
import okhttp3.Response;

import java.io.IOException;
import java.util.Arrays;
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
        GtRequest request = new GtRequest();
        Response response = request.get(baseUrl+"abvjashdfabvjaskdfjkhsdfj");
        dirErrorPageMap.put(baseUrl,response.body().bytes());
        if (response.body() == null) {
            byte[] tmp = new byte[0];
            return tmp;
        }

        if (!response.isSuccessful()) {
            return new byte[0];
        }
        return response.body().bytes();
    }
    public static boolean isPageExist(String url) throws IOException {
        GtRequest request = new GtRequest();
        Response response = request.get(url);
        if (response.code() == 404) {
            return false;
        }
        byte[] errorPage = getErrorPage(url);


        if (FuzzySearch.ratio(response.body().string(),new String(errorPage)) > 95) {
            return false;
        }
        return true;
    }
}
