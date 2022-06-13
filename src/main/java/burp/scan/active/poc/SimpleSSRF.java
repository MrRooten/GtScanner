package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.scan.active.ModuleBase;
import burp.scan.lib.poc.ReversePocClient;
import burp.scan.lib.web.WebPageInfo;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class SimpleSSRF implements ModuleBase {
    static final String SSRF_PATTERN = "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    static Pattern pattern = Pattern.compile(SSRF_PATTERN);
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        IRequestInfo reqInfo = webInfo.getReqInfo();
        var parameters = reqInfo.getParameters();
        List<Pair<Integer,Integer>> parametersRange = new ArrayList<>();
        for (var parameter : parameters) {
            String value = parameter.getValue();
            if (pattern.matcher(value).find()) {
                parametersRange.add(Pair.of(parameter.getValueStart(),parameter.getValueEnd()));
            }
        }

        if (parametersRange.size() == 0) {
            return ;
        }

        var pocClient = new ReversePocClient();
        var payload = pocClient.getPayload();
    }

    @Override
    public Set<String> getTags() {
        return null;
    }
}
