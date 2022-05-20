package test;

import burp.scan.lib.fingerprinthub.FingerPrintMatchRule;
import burp.scan.tags.TagTypes;

import java.io.FileNotFoundException;

public class Test {
    public static void main(String[] args) throws FileNotFoundException {
        FingerPrintMatchRule rule = new FingerPrintMatchRule("apache-tomcat.yaml", TagTypes.Tomcat_Java);
    }
}
