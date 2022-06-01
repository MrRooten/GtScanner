package test;

import burp.scan.lib.utils.Levenshtein;
import burp.scan.lib.web.SiteInfo;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.PageUtils;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;
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
        TagUtils.InitTags();
        SiteInfo info = new SiteInfo("http://test.com");
        info.addTag(TagTypes.ThinkPHP_PHP);
        info.addTag(TagTypes.SpringBoot_Spring);
        System.out.println(info.hasTag(TagTypes.Java_Base));
    }
}
