package burp.scan.lib.fingerprinthub;

import burp.scan.tags.TagTypes;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FingerPrintMatchRule {
    String yamlString;
    Map<String,Object> fingerMap;
    ArrayList<FingerPrint> fingerPrints = new ArrayList<>();
    TagTypes tag;

    public FingerPrintMatchRule(String file,TagTypes tag) throws FileNotFoundException {
        Yaml yaml = new Yaml();
        InputStream inputStream = new FileInputStream(file);
        Map<String,Object> obj = yaml.load(inputStream);
        ArrayList<HashMap> fingerprints = (ArrayList<HashMap>) obj.get("fingerprint");

        this.tag = tag;

    }
    public boolean isMatch(byte[] response,byte[] request) {
        return false;
    }

}
