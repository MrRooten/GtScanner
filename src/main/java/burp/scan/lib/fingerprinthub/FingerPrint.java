package burp.scan.lib.fingerprinthub;

import burp.scan.lib.GlobalFunction;
import burp.scan.lib.utils.Utils;
import burp.scan.lib.web.utils.GtResponse;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FingerPrint {
    String path;
    String match_method;
    String value;
    String finger_name;
    public FingerPrint(String match_method,String path,String value,String finger_name) {
        this.path = path;
        this.value = value;
        this.match_method = match_method;
        this.finger_name = finger_name;
    }
    boolean isMatch(byte[] request, byte[] response) {
        return false;
    }
    public static Map<String,FingerPrint> faviconHash = new HashMap<>();
    public static Map<String,FingerPrint> pathHash = new HashMap<>();
    public static void InitializeFingerPrints() {
        try {
            String fingerJsonStr = new String(Utils.ReadResourceFile("cms_finger.json"));
            JSONObject fingerprintJson = new JSONObject(fingerJsonStr);
            var fingers = fingerprintJson.getJSONArray("cms");
            for (int i=0;i < fingers.length();i++) {
                var finger = fingers.getJSONObject(i);
                String path = finger.getString("path");
                String match_method = finger.getString("options");
                String value = finger.getString("match_pattern");
                String finger_name = finger.getString("cms_name");
                if (path.contains("favicon.ico")) {
                    String hash = finger.getString("match_pattern");
                    String cmsName = finger.getString("cms_name");
                    faviconHash.put(hash,new FingerPrint(match_method,path,value,finger_name));
                }
                pathHash.put(path,new FingerPrint(match_method,path,value,finger_name));
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public String getFingerName() {
        return this.finger_name;
    }

}
