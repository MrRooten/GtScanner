package test;

import burp.scan.lib.ProcServer;
import burp.scan.lib.utils.Config;
import me.xdrop.fuzzywuzzy.FuzzySearch;

import java.io.IOException;


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
        System.out.println(FuzzySearch.ratio("apache tomcat","tomcat bbc"));
    }
}
