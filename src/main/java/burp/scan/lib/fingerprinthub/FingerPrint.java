package burp.scan.lib.fingerprinthub;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FingerPrint {
    public String path;
    public String request_method;
    public HashMap request_header;
    public String request_data;
    public Integer status;
    public HashMap headers;
    public List<String> keyword;
    public String favicon_hash;
    public FingerPrint(HashMap map) {
        this.path = (String) map.get("path");
        this.request_method = (String) map.get("request_method");
        this.request_header = (HashMap) map.get("request_header");
        this.request_data = (String) map.get("request_data");
        this.status = (Integer) map.get("status");
        this.headers = (HashMap) map.get("headers");
        this.keyword = (List<String>) map.get("keyword");
        this.favicon_hash = (String) map.get("favicon_hash");
    }

    boolean isMatch(byte[] request, byte[] response) {
        return false;
    }
}
