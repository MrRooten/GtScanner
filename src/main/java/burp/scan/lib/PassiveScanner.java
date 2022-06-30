package burp.scan.lib;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.feature.Disable;
import burp.scan.active.feature.RunOnce;
import burp.scan.lib.utils.Config;
import burp.scan.lib.web.WebPageInfo;

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
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;


public class PassiveScanner {

    static List<ModuleBase> getModules() {
        List<String> modules = null;
        List<ModuleBase> result = new ArrayList<>();
        try {
            modules = getClassNamesFromPackage("burp.scan.active.poc.");
            for (String module : modules) {
                if (module.contains("$")) {
                    continue;
                }

                Constructor<?> c = Class.forName("burp.scan.active.poc." + module).getConstructor();
                ModuleBase gtModule = (ModuleBase) c.newInstance();
                for (Method m : gtModule.getClass().getMethods()) {
                    if (m.getName().equals("scan")) {
                        result.add(gtModule);
                    }
                }
            }
        } catch (IOException | ClassNotFoundException | InvocationTargetException | NoSuchMethodException | InstantiationException | IllegalAccessException e) {
            e.printStackTrace();
        }
        return result;
    }

    static List<PassiveRule> getPassiveModules() {
        List<String> modules = null;
        List<PassiveRule> result = new ArrayList<>();
        try {
            modules = getClassNamesFromPackage("burp.scan.passive.");
            for (String module : modules) {
                if (module.contains("$")) {
                    continue;
                }

                Constructor<?> c = Class.forName("burp.scan.passive." + module).getConstructor();
                PassiveRule gtModule = (PassiveRule) c.newInstance();
                for (Method m : gtModule.getClass().getMethods()) {
                    if (m.getName().equals("scan")) {
                        result.add(gtModule);
                    }
                }
            }
        } catch (IOException | ClassNotFoundException | InvocationTargetException | NoSuchMethodException | InstantiationException | IllegalAccessException e) {
            GlobalFunction.callbacks.printOutput(e.getMessage());
        }
        return result;
    }
    static List<ModuleBase> ACTIVE_MODULES = getModules();
    static List<PassiveRule> PASSIVE_RULES = getPassiveModules();
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
            GlobalFunction.callbacks.printOutput(contents.toString());
            String entryName;
            for (File actual : contents) {
                entryName = actual.getCanonicalPath();
                names.add(entryName);
            }
        }
        return names;
    }

    public static boolean isValidContentType(String contentTypeResponse) {
        do {
            if (contentTypeResponse == null) {
                return true;
            }

            if (contentTypeResponse.contains("text")) {
                return true;
            }

            if (contentTypeResponse.contains("application")) {
                if (contentTypeResponse.contains("json")) {
                    return true;
                }

                if (contentTypeResponse.contains("xml")) {
                    return true;
                }

            }

        }while(false);

        return false;
    }
    public static List<IScanIssue> scanVulnerabilities(IHttpRequestResponse baseRequestResponse,
                                           IBurpExtenderCallbacks callbacks) {
        long startTime = System.nanoTime();
        IExtensionHelpers helpers = callbacks.getHelpers();
        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] rawResponse = baseRequestResponse.getResponse();
        int MAX_SIZE = 1024*1024*5;
        if (rawResponse.length > MAX_SIZE) {
            return null;
        }

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        IResponseInfo respInfo = helpers.analyzeResponse(rawResponse);
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(),true);
        //Body (without the headers)
        String reqBody = null;
        String respBody = null;

        String httpServerHeader = HTTPParser.getResponseHeaderValue(respInfo, "Server");
        String contentTypeResponse = HTTPParser.getResponseHeaderValue(respInfo, "Content-Type");

        if (contentTypeResponse!=null && !isValidContentType(contentTypeResponse)) {
            return null;
        } else {
            reqBody = getBodySection(rawRequest, reqInfo.getBodyOffset());
            respBody = getBodySection(rawResponse, respInfo.getBodyOffset());
        }
        String xPoweredByHeader = HTTPParser.getResponseHeaderValue(respInfo, "X-Powered-By");
        WebPageInfo webInfo = new WebPageInfo(baseRequestResponse,reqBody,respBody,reqInfo,respInfo);
        webInfo.setConfig(Config.getInstance());
        //Before Passive Scan and Active Scan

        callbacks.printOutput("PASSIVE_RULES length:"+PASSIVE_RULES.size());
        for(PassiveRule scanner : PASSIVE_RULES) {
            try {
                scanner.scan(callbacks, baseRequestResponse, reqBody, respBody, reqInfo, respInfo,
                        httpServerHeader, contentTypeResponse, xPoweredByHeader, webInfo);
            } catch (Exception e) {
                callbacks.printError(e.getMessage());
            }
        }

        long endTime   = System.nanoTime();
        long totalTime = endTime - startTime;
        callbacks.printOutput("Passive Page Cost Time:"+totalTime);
        stdout.println(webInfo.getSiteInfo().getHost() + ":" + webInfo.getSiteInfo().getTags().toString());
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        for (ModuleBase module : ACTIVE_MODULES) {
            if (module instanceof Disable) {
                continue;
            }
            if (webInfo.getSiteInfo().containsRunnedModule(module)) {
                if (module instanceof RunOnce) {
                    continue;
                }
            }
            Set<String> tags = module.getTags();
            if (module.getTags()==null||webInfo.getSiteInfo().hasTags(module.getTags())) {
                if (module instanceof Disable) {
                    continue;
                }
                try {
                    module.scan(callbacks, webInfo);
                } catch (Exception e) {
                    callbacks.printError(e.getLocalizedMessage());
                }
                webInfo.getSiteInfo().addRunnedModule(module);
            }

        }

        return webInfo.getIssues();
    }


    private static String getBodySection(byte[] respBytes, int bodyOffset) {
        return new String(respBytes, bodyOffset, respBytes.length - bodyOffset);
    }
}
