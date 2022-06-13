package burp.scan.lib.web.utils;

import burp.scan.lib.RequestParser;
import okhttp3.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GtRequest {
    String method;
    String url;
    String protocol;
    List<String> headers;
    byte[] body;
    Request request;
    boolean isHttps = false;

    void buildRequest() {
        var requestBuilder = new Request.Builder();
        Headers.Builder headerBuilder = new Headers.Builder();
        for (String hh : headers) {
            Integer splitIndex = hh.indexOf(":");
            String key = hh.substring(0,splitIndex);
            key = key.trim();
            String value = hh.substring(splitIndex+1);
            value = value.trim();
            headerBuilder.add(key, value);
        }

        Headers headers = headerBuilder.build();
        RequestBody body = null;
        if (this.body != null) {
            body = RequestBody.create(this.body);
        }
        this.request = requestBuilder.url(this.url).method(this.method.toUpperCase(),body).headers(headers).build();
    }

    public GtRequest(String method, String url, String protocol,List<String> headers,byte[] body) {
        this.method = method;
        GtURL u = new GtURL(url);
        if (u.getProtocol().equalsIgnoreCase("https")) {
            this.isHttps = true;
        }
        this.url = url;
        this.protocol = protocol;
        this.headers = headers;
        this.body = body;
        buildRequest();
    }

    public GtRequest(String url) {
        this.method = "get";
        GtURL u = new GtURL(url);
        if (u.getProtocol().equalsIgnoreCase("https")) {
            this.isHttps = true;
        }
        this.url = url;
        this.protocol = "HTTP/1.1";
        this.headers = new ArrayList<>();
        this.headers.add("Host: " + u.getHost());
        this.headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Ch02.0.5005.63 Safari/537.36rome/1");
        this.headers.add("Accept: */*");
        this.body = null;
        buildRequest();
    }

    public void setHeader(String header) {
        var as = header.split(":",2);
        if (as.length != 2) {
            return ;
        }
        var hKey = as[0].trim();
        var hValue = as[1].trim();
        for (var i=0;i < this.headers.size();i++) {
            var h = this.headers.get(i);
            var tmp = h.split(":",2);
            if (tmp.length != 2) {
                continue;
            }
            var key = tmp[0].trim();
            var value = tmp[1].trim();
            if (key.equalsIgnoreCase(hKey)) {
                this.headers.set(i,header);
            }
        }

        this.headers.add(header);
    }

    public void setHeader(String name,String value) {
        for (var i=0;i < this.headers.size();i++) {
            var h = this.headers.get(i);
            var tmp = h.split(":",2);
            if (tmp.length != 2) {
                continue;
            }
            var key = tmp[0].trim();
            var v = tmp[1].trim();
            if (key.equalsIgnoreCase(name)) {
                this.headers.set(i,name + ": " + value);
            }
        }

        this.headers.add(name+": "+value);
    }

    public void setHeader(String name,String value,int index) {
        for (var i=0;i < this.headers.size();i++) {
            var h = this.headers.get(i);
            var tmp = h.split(":",2);
            if (tmp.length != 2) {
                continue;
            }
            var key = tmp[0].trim();
            var v = tmp[1].trim();
            if (key.equalsIgnoreCase(name)) {
                this.headers.set(i,name + ": " + value);
            }
        }

        this.headers.add(index,name+": "+value);
    }

    public GtRequest(byte[] request,boolean isHttps) {
        RequestParser parser = new RequestParser(request);
        this.method = parser.getMethod();
        if (isHttps) {
            this.url = "https://" + parser.getHost() + parser.getUrl();
        } else {
            this.url = "http://" + parser.getHost() + parser.getUrl();
        }
        this.protocol = parser.getProtocol();
        this.isHttps = isHttps;
        List<String> headers = new ArrayList<>();
        for (var h : parser.getHeaders().entrySet()) {
            String header = h.getKey() + ": " + h.getValue();
            headers.add(header);
        }
        this.headers = headers;
        if (parser.getBody() != null) {
            this.body = parser.getBody().getBytes(StandardCharsets.UTF_8);
        }
        buildRequest();
    }

    public GtResponse send() throws IOException {
        OkHttpClient client = null;
        if (this.protocol.equalsIgnoreCase("HTTP/2")) {
            client = new OkHttpClient().newBuilder().protocols(Arrays.asList(Protocol.HTTP_2)).build();
        } else if (this.protocol.equalsIgnoreCase("HTTP/1.1")) {
            client = new OkHttpClient().newBuilder().protocols(Arrays.asList(Protocol.HTTP_1_1)).build();
        } else if (this.protocol.equalsIgnoreCase("HTTP/1.0")) {
            client = new OkHttpClient().newBuilder().protocols(Arrays.asList(Protocol.HTTP_1_0)).build();
        } else {
            client = new OkHttpClient().newBuilder().protocols(Arrays.asList(Protocol.HTTP_1_1)).build();
        }

        Response response = client.newCall(this.request).execute();
        return new GtResponse(this,response);
    }

    public Request getRequest() {
        return this.request;
    }
    public byte[] raw() {
        StringBuilder result = new StringBuilder();
        result.append(this.method);
        result.append(" ");
        result.append(this.url);
        result.append(" ");
        result.append(this.protocol);
        result.append("\r\n");
        for (var header : headers) {
            result.append(header);
            result.append("\r\n");
        }

        result.append("\r\n");
        if (this.body != null) {
            result.append(new String(this.body));
        }
        return result.toString().getBytes(StandardCharsets.UTF_8);
    }

    public String getUrl() {
        return this.url;
    }
}
