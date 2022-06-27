package burp.scan.lib.web.utils;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.scan.lib.GlobalFunction;
import burp.scan.lib.utils.GtHttpRequestResponse;
import burp.scan.lib.utils.GtHttpService;
import okhttp3.Protocol;
import okhttp3.Response;

import java.io.IOException;
import java.util.*;

public class GtResponse {
    static Map<Integer,String> statusCodeMeaning = new HashMap<>();
    static {
        statusCodeMeaning.put(100,"Continue");
        statusCodeMeaning.put(101,"Switching protocols");
        statusCodeMeaning.put(102,"Processing");
        statusCodeMeaning.put(103,"Early Hints");

        statusCodeMeaning.put(200,"OK");
        statusCodeMeaning.put(201,"Created");
        statusCodeMeaning.put(202,"Accepted");
        statusCodeMeaning.put(203,"Non-Authoritative Information");
        statusCodeMeaning.put(204,"No Content");
        statusCodeMeaning.put(205,"Reset Content");
        statusCodeMeaning.put(206,"Partial Content");
        statusCodeMeaning.put(207,"Multi-Status");
        statusCodeMeaning.put(208,"Already Reported");
        statusCodeMeaning.put(226,"IM Used");

        statusCodeMeaning.put(300,"Multiple Choices");
        statusCodeMeaning.put(301,"Moved Permanently");
        statusCodeMeaning.put(302,"Found (Previously \"Moved Temporarily\")");
        statusCodeMeaning.put(303,"See Other");
        statusCodeMeaning.put(304,"Not Modified");
        statusCodeMeaning.put(305,"Use Proxy");
        statusCodeMeaning.put(306,"Switch Proxy");
        statusCodeMeaning.put(307,"Temporary Redirect");
        statusCodeMeaning.put(308,"Permanent Redirect");

        statusCodeMeaning.put(400,"Bad Request");
        statusCodeMeaning.put(401,"Unauthorized");
        statusCodeMeaning.put(402,"Payment Required");
        statusCodeMeaning.put(403,"Forbidden");
        statusCodeMeaning.put(404,"Not Found");
        statusCodeMeaning.put(405,"Method Not Allowed");
        statusCodeMeaning.put(406,"Not Acceptable");
        statusCodeMeaning.put(407,"Proxy Authentication Required");
        statusCodeMeaning.put(408,"Request Timeout");
        statusCodeMeaning.put(409,"Conflict");
        statusCodeMeaning.put(410,"Gone");
        statusCodeMeaning.put(411,"Length Required");
        statusCodeMeaning.put(412,"Precondition Failed");
        statusCodeMeaning.put(413,"Payload Too Large");
        statusCodeMeaning.put(414,"URI Too Long");
        statusCodeMeaning.put(415,"Unsupported Media Type");
        statusCodeMeaning.put(416,"Range Not Satisfiable");
        statusCodeMeaning.put(417,"Expectation Failed");
        statusCodeMeaning.put(418,"I'm a Teapot");
        statusCodeMeaning.put(421,"Misdirected Request");
        statusCodeMeaning.put(422,"Unprocessable Entity");
        statusCodeMeaning.put(423,"Locked");
        statusCodeMeaning.put(424,"Failed Dependency");
        statusCodeMeaning.put(425,"Too Early");
        statusCodeMeaning.put(426,"Upgrade Required");
        statusCodeMeaning.put(428,"Precondition Required");
        statusCodeMeaning.put(429,"Too Many Requests");
        statusCodeMeaning.put(431,"Request Header Fields Too Large");
        statusCodeMeaning.put(451,"Unavailable For Legal Reasons");

        statusCodeMeaning.put(500,"Internal Server Error");
        statusCodeMeaning.put(501,"Not Implemented");
        statusCodeMeaning.put(502,"Bad Gateway");
        statusCodeMeaning.put(503,"Service Unavailable");
        statusCodeMeaning.put(504,"Gateway Timeout");
        statusCodeMeaning.put(505,"HTTP Version Not Supported");
        statusCodeMeaning.put(506,"Variant Also Negotiates");
        statusCodeMeaning.put(507,"Insufficient Storage");
        statusCodeMeaning.put(508,"Loop Detected");
        statusCodeMeaning.put(510,"Not Extended");
        statusCodeMeaning.put(511,"Network Authentication Required");
    }
    byte[] body;
    GtRequest request;
    Response response;
    Exception exception;
    GtHttpRequestResponse httpRequestResponse;
    IHttpRequestResponse burpRequestResponse;
    IRequestInfo burpReqInfo;
    IResponseInfo burpRespInfo;
    boolean isBurp = false;
    public byte[] getResponse() {
        return null;
    }

    public GtRequest getRequest() {
        return this.request;
    }

    public GtHttpRequestResponse getRequestResponse() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse;
        }
        GtHttpRequestResponse result = new GtHttpRequestResponse();
        result.setRequest(this.request.raw());
        result.setResponse(this.raw());
        String url = this.request.getUrl();
        GtURL u = new GtURL(url);
        GtHttpService httpService = new GtHttpService(u.getHostWithoutPort(),u.getPort(),u.getProtocol());
        result.setHttpService(httpService);
        this.httpRequestResponse = result;
        return result;
    }
    public GtResponse(Response response) {
        this.response = response;
    }

    public GtResponse(IHttpRequestResponse requestResponse) {
        this.burpRequestResponse = requestResponse;
        this.burpReqInfo = GlobalFunction.helpers.analyzeRequest(requestResponse);
        this.burpRespInfo = GlobalFunction.helpers.analyzeResponse(requestResponse.getResponse());
        this.isBurp = true;
    }

    public GtResponse(GtRequest request,Response response) {
        this.request = request;
        this.response = response;
    }
    public void setRequest(GtRequest request) {
        this.request = request;
    }

    public void setException(Exception e) {
        this.exception = e;
    }

    public int getStatudCode() {
        if (isBurp) {
            return this.burpRespInfo.getStatusCode();
        }
        return this.response.code();
    }

    public byte[] getBody() throws IOException {
        if (body != null) {
            return body;
        }

        if (isBurp) {
            var _tmp = this.burpRequestResponse.getResponse();
            this.body = Arrays.copyOfRange(_tmp,this.burpRespInfo.getBodyOffset(),_tmp.length);
            return this.body;
        }
        body = this.response.body().bytes();
        return body;
    }

    public List<String> getHeaders() {
        if (isBurp) {
            return burpRespInfo.getHeaders();
        }
        List<String> result = new ArrayList<>();
        for (var h : this.response.headers()) {
            result.add(h.getFirst()+":"+h.getSecond());
        }
        return result;
    }

    public byte[] raw() {
        if (isBurp) {
            return this.burpRequestResponse.getResponse();
        }
        StringBuilder builder = new StringBuilder();
        String protocol = "";
        if (this.response.protocol() == Protocol.HTTP_1_0) {
            protocol = "HTTP/1.0";
        } else if (this.response.protocol() == Protocol.HTTP_1_1) {
            protocol = "HTTP/1.1";
        } else if (this.response.protocol() == Protocol.HTTP_2) {
            protocol = "HTTP/2";
        }
        builder.append(protocol);
        builder.append(" ");
        builder.append(this.getStatudCode());
        builder.append(" ");
        builder.append(statusCodeMeaning.get(this.getStatudCode()));
        builder.append("\r\n");
        for (var header : this.response.headers()) {
            builder.append(header.getFirst() + ": " + header.getSecond() + "\r\n");
        }
        builder.append("\r\n");

        try {
            builder.append(new String(this.getBody()));
        } catch (IOException e) {
        }

        return builder.toString().getBytes();
    }

    public String getHeaderValue(String name) {
        return null;
    }
}
