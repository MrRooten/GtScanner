package burp.scan.lib;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class RequestParser {
    byte[] request;
    String method;
    String url;
    String protocol;
    LinkedHashMap<String,String> headers = new LinkedHashMap<>();
    String body;
    public RequestParser(byte[] request) {
        this.request = request;
        String reqString = new String(request);
        String[] sp = reqString.split("(\r\n\r\n)|(\n\n)");
        String _headers = sp[0].trim();
        String[] _bodys = null;
        String body = null;
        if (sp.length >= 2) {
            _bodys = Arrays.copyOfRange(sp,1,sp.length);
            body = String.join("", _bodys);
        }
        this.body = body;
        var headers = _headers.split("(\r\n)|(\n)");
        for (int i=0;i < headers.length;i++) {
            if (i == 0) {
                var first = headers[i].split(" ");
                this.method = first[0].trim();
                this.url = first[1].trim();
                this.protocol = first[2].trim();
                continue;
            }
            int splitIndex = headers[i].indexOf(":");
            String key = headers[i].substring(0,splitIndex).trim();
            String value = headers[i].substring(splitIndex+1).trim();
            this.headers.put(key,value.trim());
        }
    }

    public String getHost() {
        return this.headers.get("Host");
    }

    public String getMethod() {
        return this.method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getProtocol() {
        return this.protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getBody() {
        return this.body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public Map<String,String> getHeaders() {
        return this.headers;
    }

    public void setHeaders(Map<String,String> headers) {
        for (var header : headers.keySet()) {
            this.headers.put(header,headers.get(header));
        }
    }

    public void setHeader(String name,String value) {
        this.headers.put(name,value);
    }
    public String getHeaderValue(String name) {
        return this.headers.get(name);
    }

    public byte[] bytes() {
        StringBuilder result = new StringBuilder();
        result.append(this.method);
        result.append(" ");
        result.append(this.url);
        result.append(" ");
        result.append(this.protocol);
        result.append("\r\n");
        for (var header : headers.entrySet()) {
            result.append(header.getKey()+": " + header.getValue());
            result.append("\r\n");
        }

        result.append("\r\n");
        if (this.body != null) {
            result.append(this.body);
        }
        return result.toString().getBytes(StandardCharsets.UTF_8);
    }

    public RequestInfoParser getRequestInfo() {
        return new RequestInfoParser(GlobalFunction.helpers.analyzeRequest(this.bytes()));
    }
}
