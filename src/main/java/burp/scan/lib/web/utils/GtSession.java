package burp.scan.lib.web.utils;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.scan.lib.GlobalFunction;
import burp.scan.lib.utils.GlobalConfig;
import okhttp3.*;

import javax.net.ssl.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

class SSLSocketClientUtil {

    public static SSLSocketFactory getSocketFactory(TrustManager manager) {
        SSLSocketFactory socketFactory = null;
        try {
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, new TrustManager[]{manager}, new SecureRandom());
            socketFactory = sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        return socketFactory;
    }

    public static X509TrustManager getX509TrustManager() {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    public static HostnameVerifier getHostnameVerifier() {
        HostnameVerifier hostnameVerifier = new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        };
        return hostnameVerifier;
    }


}
public class GtSession {
    OkHttpClient client;
    static List<String> defalutHeaders = new ArrayList<>();
    static {
        defalutHeaders.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0");
        defalutHeaders.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
        defalutHeaders.add("Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2");
        defalutHeaders.add("Accept-Encoding: gzip, deflate");
        defalutHeaders.add("Connection: close");


    }
    X509TrustManager manager = SSLSocketClientUtil.getX509TrustManager();
    public GtSession(Protocol protocol) {

        client = new OkHttpClient().newBuilder().protocols(Arrays.asList(protocol)).build();
    }

    public GtSession(Request request) {

    }
    public GtSession() {
        client = new OkHttpClient();
    }
    static GtSession globalSession;
    public static GtSession getGlobalSession() {
        if(globalSession != null) {
            return globalSession;
        }
        globalSession = new GtSession();
        globalSession.setProxy(GlobalConfig.getInstance().getValue("network.proxy"));
        return globalSession;
    }
    public void setProxy(String proxyString) {
        Proxy.Type type;
        if (proxyString.trim().length() == 0) {
            type = Proxy.Type.DIRECT;
            Proxy pp = Proxy.NO_PROXY;
            client = client.newBuilder().sslSocketFactory(SSLSocketClientUtil.getSocketFactory(manager),manager).
                    hostnameVerifier(SSLSocketClientUtil.getHostnameVerifier()).proxy(pp).build();
            return ;
        }
        GtURL url = new GtURL(proxyString);
        if (url.getProtocol().startsWith("http")) {
            type = Proxy.Type.HTTP;
            setProxy(type,url.getHostWithoutPort(),url.getPort());
            return ;
        }

    }

    public void setProxy(Proxy.Type type,String host,int port) {
        Proxy pp = new Proxy(type,new InetSocketAddress(host,port));
        client = client.newBuilder().sslSocketFactory(SSLSocketClientUtil.getSocketFactory(manager),manager).
                hostnameVerifier(SSLSocketClientUtil.getHostnameVerifier()).proxy(pp).build();
    }
    public IHttpRequestResponse burpGet(String url) throws IOException {
        GtURL u = new GtURL(url);
        String host = u.getHost();
        int port = u.getPort();
        String protocol = u.getProtocol();
        boolean isHttps = false;
        if (protocol.equals("https")) {
            isHttps = true;
        } else {
            isHttps = false;
        }
        byte[] headOfRequest = GlobalFunction.helpers.buildHttpRequest(u.getURL());
        byte[] restOfRequest = GlobalFunction.helpers.buildHttpMessage(defalutHeaders,null);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write( headOfRequest );
        //outputStream.write( restOfRequest );
        byte[] request = outputStream.toByteArray();
        IHttpService httpService = GlobalFunction.helpers.buildHttpService(host,port,isHttps);
        IHttpRequestResponse result = GlobalFunction.callbacks.makeHttpRequest(httpService,request);
        return result;
    }

    public GtResponse get(String url) throws IOException {
        Request request = new Request.Builder().get().url(url).build();
        Response resp;
        resp = client.newCall(request).execute();
        return new GtResponse(resp);
    }

    public IHttpRequestResponse burpGet(String url,List<String> headers) throws IOException {
        GtURL u = new GtURL(url);
        String host = u.getHost();
        int port = u.getPort();
        String protocol = u.getProtocol();
        boolean isHttps = false;
        if (protocol.equals("https")) {
            isHttps = true;
        } else {
            isHttps = false;
        }
        byte[] headOfRequest = ("GET " + u.getUrl() + "\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] hostOfRequest = ("Host: " + u.getHost() + "\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] restOfRequest = GlobalFunction.helpers.buildHttpMessage(headers,null);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write( headOfRequest );
        outputStream.write(hostOfRequest);
        outputStream.write( restOfRequest );
        byte[] request = outputStream.toByteArray();
        IHttpService httpService = GlobalFunction.helpers.buildHttpService(host,port,isHttps);
        IHttpRequestResponse result = GlobalFunction.callbacks.makeHttpRequest(httpService,request);
        return result;
    }

    public GtResponse get(String url,List<String> headers) throws IOException {
        Headers.Builder builder = new Headers.Builder();
        for (String hh : headers) {
            Integer splitIndex = hh.indexOf(":");
            String key = hh.substring(0,splitIndex);
            key = key.trim();
            String value = hh.substring(splitIndex);
            value = value.trim();
            builder.add(key, value);
        }
        Headers h = builder.build();
        Request request = new Request.Builder().url(url).headers(h).build();
        Response response = client.newCall(request).execute();
        return new GtResponse(response);
    }
    public enum ContentType {
        JSON,
        MULTIPART_FORM_DATA,
    }
    public IHttpRequestResponse burpPost(String url,byte[] data,ContentType contentType) {
        GtURL u = new GtURL(url);
        String host = u.getHost();
        int port = u.getPort();
        String protocol = u.getProtocol();
        boolean isHttps = false;
        if (protocol.equals("https")) {
            isHttps = true;
        } else {
            isHttps = false;
        }
        return null;
    }
    public GtResponse post(String url,byte[] data,String mediaType) throws IOException {
        MediaType type = MediaType.parse(mediaType);
        RequestBody body = RequestBody.create(type,data);
        Request request = new Request.Builder().url(url).post(body).build();
        Response response = client.newCall(request).execute();
        return new GtResponse(response);
    }

    public GtResponse post(String url, List<String> headers,byte[] data,String mediaType) throws IOException {
        Headers.Builder builder = new Headers.Builder();
        for (String hh : headers) {
            Integer splitIndex = hh.indexOf(":");
            String key = hh.substring(0,splitIndex);
            key = key.trim();
            String value = hh.substring(splitIndex);
            value = value.trim();
            builder.add(key, value);
        }
        MediaType type = MediaType.parse(mediaType);
        RequestBody body = RequestBody.create(type,data);
        Request request = new Request.Builder().url(url).headers(builder.build()).post(body).build();
        Response response = client.newCall(request).execute();
        return new GtResponse(response);
    }

    public byte[] toRequestBytes(Request request) {
        StringBuffer reqString = new StringBuffer();
        reqString.append(request.method());
        reqString.append(" ");
        reqString.append(request.url().encodedPath());
        reqString.append(" ");
        String protocol = "";
        if (client.protocols().get(0) == Protocol.HTTP_1_1) {
            protocol = "HTTP/1.1";
        } else if (client.protocols().get(0) == Protocol.HTTP_1_0) {
            protocol = "HTTP/1.0";
        } else if (client.protocols().get(0) == Protocol.HTTP_2) {
            protocol = "HTTP/2";
        } else if (client.protocols().get(0) == Protocol.SPDY_3) {
            protocol = "SPDY/3";
        }

        reqString.append(protocol);
        reqString.append("\r\n");
        Headers headers = request.headers();
        for (String name : headers.names()) {
            String value = headers.get(name);
            String headerString = name + value + "\r\n";
            reqString.append(headerString);
        }
        reqString.append("\r\n");
        if (request.body() != null) {
            reqString.append(Objects.requireNonNull(request.body()).toString());
            reqString.append("\r\n");
        }

        return reqString.toString().getBytes(StandardCharsets.UTF_8);
    }

    public GtResponse sendRequest(GtRequest request) throws IOException {
        Request req = request.getRequest();
        var res = this.client.newCall(req).execute();
        return new GtResponse(request,res);
    }
}
