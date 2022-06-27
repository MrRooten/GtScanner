package burp.scan.lib.utils;

import burp.BurpExtender;
import burp.scan.lib.GlobalFunction;
import org.apache.tomcat.util.http.fileupload.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Utils {
    static ClassLoader cldr = BurpExtender.class.getClassLoader();
    public static URL GetResourceFile(String filename) {
        return cldr.getResource(filename);
    }

    public static byte[] ReadResourceFile(String filename) throws IOException {
        var url = GetResourceFile(filename);
        InputStream in = url.openStream();
        return in.readAllBytes();
    }
}
