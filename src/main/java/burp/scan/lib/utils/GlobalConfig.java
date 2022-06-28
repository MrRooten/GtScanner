package burp.scan.lib.utils;

import org.json.JSONObject;

public class GlobalConfig {
    static GlobalConfig instance;
    JSONObject config = new JSONObject();
    public String getValue(String name) {
        String[] keys = name.trim().split("\\.");
        JSONObject curr = config;
        for (int i=0;i < keys.length-1;i++) {
            if (curr.has(keys[i])) {
                curr = config.getJSONObject(keys[i]);
            } else {
                return "";
            }
        }

        try {
            return curr.getString(keys[keys.length-1]);
        } catch (Exception e) {
            return "";
        }
    }

    public void setValue(String name,String value) {
        String[] keys = name.trim().split("\\.");
        JSONObject curr = config;
        for (int i=0;i < keys.length-1;i++) {
            if (curr.has(keys[i])) {
                curr = config.getJSONObject(keys[i]);
            } else {
                var obj = new JSONObject();
                curr.put(keys[i],obj);
                curr = config.getJSONObject(keys[i]);
            }
        }

        curr.put(keys[keys.length-1],value);
    }

    public String toJsonString() {
        return this.config.toString();
    }

    public void initialize(String jsonString) {
        JSONObject object = new JSONObject(jsonString);
        this.config = object;
    }
    public static GlobalConfig getInstance() {
        if (instance != null) {
            return instance;
        }

        instance = new GlobalConfig();
        return instance;
    }
}
