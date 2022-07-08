package test;

import burp.scan.lib.ProcServer;
import burp.scan.lib.utils.Config;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;

import java.io.IOException;


public class Test {
    static String payload = """
            GET / HTTP/1.1
            Host: baidu.com
            Accept-Encoding: gzip, deflate
            Accept: */*
            Accept-Language: en
            User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
            Connection: close
            Content-Type: application/json
            Content-Length: 328

            """;
    public static void test() {
        var b = Thread.currentThread().getStackTrace()[2];
        System.out.println(b.toString());
    }
    public static void main(String[] args) throws IOException {
        var request = new GtRequest("https://cn.bing.com");
        var session = new GtSession();
        var response = session.sendRequest(request);
        System.out.println(new String(response.getBody()));
    }
}
