package test;

import burp.scan.lib.utils.Levenshtein;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.PageUtils;
import me.xdrop.fuzzywuzzy.FuzzySearch;
import okhttp3.Protocol;
import okhttp3.Response;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import me.xdrop.fuzzywuzzy.ratios.SimpleRatio;


public class Test {
    public static void main(String[] args) {
        //FingerPrintMatchRule rule = new FingerPrintMatchRule("apache-tomcat.yaml", TagTypes.Tomcat_Java);
        try {
            System.out.println(PageUtils.isPageExist("https://bing.com/err234324"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
