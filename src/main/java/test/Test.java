package test;

import burp.scan.lib.utils.Levenshtein;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.PageUtils;
import me.xdrop.fuzzywuzzy.FuzzySearch;
import okhttp3.Protocol;
import okhttp3.Response;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import me.xdrop.fuzzywuzzy.ratios.SimpleRatio;


public class Test {
    public static void main(String[] args) throws MalformedURLException {
        //FingerPrintMatchRule rule = new FingerPrintMatchRule("apache-tomcat.yaml", TagTypes.Tomcat_Java);

        var url = new URL("https://cn.bing.com/hp/api/v1/trivia?format=json&id=HPQuiz_20220530_MountFryatt&mkt=zh-CN");
        System.out.println(url.getPort());
    }
}
