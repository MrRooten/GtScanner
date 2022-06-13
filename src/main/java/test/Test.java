package test;

import burp.scan.lib.RequestParser;
import burp.scan.lib.utils.BytesUtils;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtSession;

import java.io.IOException;
import java.net.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;


public class Test {
    static String payload = "POST /_ignition/execute-solution HTTP/1.1\n" +
            "Host: 192.168.43.10:8083\n" +
            "Accept-Encoding: gzip, deflate\n" +
            "Accept: */*\n" +
            "Accept-Language: en\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36\n" +
            "Connection: close\n" +
            "Content-Type: application/json\n" +
            "Content-Length: 328\n" +
            "\n" +
            "{\n" +
            "  \"solution\": \"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution\",\n" +
            "  \"parameters\": {\n" +
            "    \"variableName\": \"username\",\n" +
            "    \"viewFile\": \"xxxxxx\"\n" +
            "  }\n" +
            "}";
    public static void test() {
        var b = Thread.currentThread().getStackTrace()[2];
        System.out.println(b.toString());
    }
    public static void main(String[] args) throws IOException {
        GtSession session = new GtSession();
        session.setProxy("http://127.0.0.1:8080");
        GtRequest request = new GtRequest(payload.getBytes(),false);
        var res = session.sendRequest(request);
        System.out.println(new String(res.getBody()));
    }
}
