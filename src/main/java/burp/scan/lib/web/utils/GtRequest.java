package burp.scan.lib.web.utils;

import burp.IRequestInfo;
import okhttp3.*;
import okhttp3.internal.framed.Header;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GtRequest {
    OkHttpClient client;
    public GtRequest(Protocol protocol) {
        client = new OkHttpClient().newBuilder().protocols(Arrays.asList(protocol)).build();
    }

    public GtRequest() {
        client = new OkHttpClient();
    }

    public Response get(String url) throws IOException {
        Request request = new Request.Builder().get().url(url).build();
        Response resp;
        resp = client.newCall(request).execute();
        return resp;
    }

    public Response get(String url,List<String> headers) throws IOException {
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
        return response;
    }

    public Response post(String url,byte[] data,String mediaType) throws IOException {
        MediaType type = MediaType.parse(mediaType);
        RequestBody body = RequestBody.create(type,data);
        Request request = new Request.Builder().url(url).post(body).build();
        Response response = client.newCall(request).execute();
        return response;
    }

    public Response post(String url, List<String> headers,byte[] data,String mediaType) throws IOException {
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
        return response;
    }

    public byte[] toRequestBytes(Request request) {
        StringBuffer reqString = new StringBuffer();
        reqString.append(request.method());
        reqString.append(" ");
        reqString.append(request.url().encodedPath());
        reqString.append(" ");
        String protocol = new String();
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
            reqString.append(request.body().toString());
            reqString.append("\r\n");
        }

        return reqString.toString().getBytes(StandardCharsets.UTF_8);
    }
}
