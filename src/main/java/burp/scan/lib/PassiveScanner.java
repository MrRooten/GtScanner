package burp.scan.lib;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.passive.*;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;


public class PassiveScanner {

    /**
     * List of passive rules
     */
    static PassiveRule[] PASSIVE_RULES = {new ApacheTomcatRule(),
            new ExceptionRule(),
            new HttpServerHeaderRule(),
            new SqlQueryRule(),
            new ApacheStrutsS2023Rule(),
            new JettyRule(),
            new SessionIDInURL(),
            new JSPostMessage(),
            new SessionFixation(),
            new NginxRule(),
            new ApacheRule()
    };

    public static ArrayList<String> getClassNamesFromPackage(String packageName) throws IOException {
        URL packageURL;
        ArrayList<String> names = new ArrayList<>();

        packageName = packageName.replace(".", "/");
        packageURL = PassiveScanner.class.getClassLoader().getResource(packageName);

        if ((packageURL != null) && (packageURL.getProtocol().equals("jar"))) {
            String jarFileName;
            JarFile jf;
            Enumeration<JarEntry> jarEntries;
            String entryName;

            // build jar file name, then loop through zipped entries
            jarFileName = URLDecoder.decode(packageURL.getFile(), "UTF-8");
            jarFileName = jarFileName.substring(5, jarFileName.indexOf("!"));
            jf = new JarFile(jarFileName);
            jarEntries = jf.entries();
            while (jarEntries.hasMoreElements()) {
                entryName = jarEntries.nextElement().getName();
                if (entryName.startsWith(packageName) && entryName.length() > packageName.length() + 5) {
                    entryName = entryName.substring(packageName.length(), entryName.lastIndexOf('.'));
                    names.add(entryName.replace("/", ""));
                }
            }

            // loop through files in classpath
        } else {
            File folder = new File(packageURL.getFile());
            File[] contents = folder.listFiles();
            String entryName;
            for (File actual : contents) {
                entryName = actual.getCanonicalPath();
                names.add(entryName);
            }
        }
        return names;
    }
    public static void scanVulnerabilities(IHttpRequestResponse baseRequestResponse,
                                           IBurpExtenderCallbacks callbacks) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] rawResponse = baseRequestResponse.getResponse();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        IResponseInfo respInfo = helpers.analyzeResponse(rawResponse);
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(),true);
        //Body (without the headers)
        String reqBody = getBodySection(rawRequest, reqInfo.getBodyOffset());
        String respBody = getBodySection(rawResponse, respInfo.getBodyOffset());

        String httpServerHeader = HTTPParser.getResponseHeaderValue(respInfo, "Server");
        String contentTypeResponse = HTTPParser.getResponseHeaderValue(respInfo, "Content-Type");
        String xPoweredByHeader = HTTPParser.getResponseHeaderValue(respInfo, "X-Powered-By");
        WebPageInfo webInfo = new WebPageInfo();
        webInfo.setRequest(rawRequest);
        webInfo.setResponse(rawResponse);
        webInfo.setHttpRequestResponse(baseRequestResponse);
        for(PassiveRule scanner : PASSIVE_RULES) {
            scanner.scan(callbacks,baseRequestResponse,reqBody,respBody,reqInfo,respInfo,
                    httpServerHeader,contentTypeResponse, xPoweredByHeader,webInfo);
        }
        stdout.println(reqInfo.getUrl()+ ":" + webInfo.tags.toString());
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        try {
            List<String> modules = getClassNamesFromPackage("burp.scan.active.poc.");
            for (String module : modules) {
                if (module.contains("$")) {
                    continue;
                }

                Constructor<?> c = Class.forName("burp.scan.active.poc." + module).getConstructor();
                ModuleBase gtModule = (ModuleBase) c.newInstance();
                for (Method m : gtModule.getClass().getMethods()) {
                    if (m.getName().equals("scan")) {
                        gtModule.scan(callbacks,webInfo);
                    }
                }
            }
        } catch (IOException | IllegalAccessException | InstantiationException | InvocationTargetException | NoSuchMethodException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }


    private static String getBodySection(byte[] respBytes, int bodyOffset) {
        return new String(respBytes, bodyOffset, respBytes.length - bodyOffset);
    }
}
