package burp.scan.lib.utils;

public class GlobalConfig {
    static GlobalConfig instance;

    public String getValue(String name) {
        return "";
    }

    public static GlobalConfig getInstance() {
        if (instance != null) {
            return instance;
        }

        instance = new GlobalConfig();
        return instance;
    }
}
