package burp.scan.lib;

import burp.scan.active.ModuleBase;
import burp.scan.lib.utils.Config;
import burp.scan.lib.utils.Logger;
import com.yevdo.jwildcard.JWildcard;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

class ResultMessage {
    String type;
    String message;

    public ResultMessage() {

    }

    public void setType(String type) {
        this.type = type;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String toJsonString() {
        JSONObject object = new JSONObject();
        object.put("type", this.type);
        object.put("message", this.message);
        return object.toString();
    }

    static public String NewErrorMessage(String message) {
        var resultMessage = new ResultMessage();
        resultMessage.setMessage(message);
        resultMessage.setType("error");
        return resultMessage.toJsonString();
    }

    static public String NewSuccessMessage() {
        var resultMessage = new ResultMessage();
        resultMessage.setMessage("Ok");
        resultMessage.setType("success");
        return resultMessage.toJsonString();
    }

}

class Handler implements Runnable {
    void err(String message, OutputStream outputStream) throws IOException {
        var logger = Logger.getLogger(Logger.Level.Debug);
        logger.error(message);
        var result = ResultMessage.NewErrorMessage(message);
        outputStream.write(result.getBytes());
    }

    void success(OutputStream outputStream) throws IOException {
        var result = ResultMessage.NewSuccessMessage();
        outputStream.write(result.getBytes());
    }
    InputStream inputStream;
    OutputStream outputStream;

    public void setStream(InputStream inputStream, OutputStream outputStream) {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
    }
    ArrayList<String> getClassNamesFromPackage(String packageName) throws IOException {
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
                entryName = actual.getName();
                entryName = entryName.substring(0,entryName.indexOf("."));
                names.add(entryName);
            }
        }
        return names;
    }
    static Map<String,ModuleBase> snake_caseModules = new HashMap<>();
    List<String> getModules() {
        List<String> modules = null;
        List<String> result = new ArrayList<>();
        var logger = Logger.getLogger(Logger.Level.Debug);
        try {
            modules = getClassNamesFromPackage("burp.scan.active.poc.");
            for (String module : modules) {
                if (module.contains("$")) {
                    continue;
                }
                try {
                    Constructor<?> c = Class.forName("burp.scan.active.poc." + module).getConstructor();
                    ModuleBase gtModule = (ModuleBase) c.newInstance();
                    for (Method m : gtModule.getClass().getMethods()) {
                        if (m.getName().equals("scan")) {
                            result.add(module);
                            snake_caseModules.put(to_snake_case(module),gtModule);
                        }
                    }
                } catch (Exception e) {
                    logger.debug(e.getMessage());
                    continue;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    String to_snake_case(String name) {
        String regex = "([a-z])([A-Z]+)";
        String replacement = "$1_$2";
        return name.replaceAll(regex, replacement)
                .toLowerCase();
    }

    List<String> getEnableModules() {
        List<String> res = new ArrayList<>();
        String _pocs = Config.getInstance().getValue("pocs.enable_pocs");
        String _free_pocs = Config.getInstance().getValue("pocs.free_pocs");
        var pocs = _pocs.split("\\s*,\\s*");
        var free_pocs = new HashSet<>(List.of(_free_pocs.split("\\s*,\\s*")));
        Set<String> allPocs = new HashSet<>();
        for (var pocEntry : snake_caseModules.entrySet()) {
            for (var poc : pocs) {
                if (pocEntry.getKey().matches(JWildcard.wildcardToRegex(poc))) {
                    allPocs.add(pocEntry.getKey());
                }
            }
        }

        for (var poc : allPocs) {
            if (snake_caseModules.containsKey(poc)) {
                res.add(poc);
            }
        }

        return res;
    }
    @Override
    public void run() {

        var logger = Logger.getLogger(Logger.Level.Debug);
        while (true) {
            byte[] b = new byte[1024];
            try {
                int len = inputStream.read(b);
                if (len == -1) {
                    continue;
                }
                String msg = new String(b, 0, len);

                JSONObject object = new JSONObject(msg);
                logger.debug("Receive message: \n" + object.toString(4));
                JSONObject resultMessage = new JSONObject();
                String action = null;
                String valueType = null;
                if (object.has("action")) {
                    action = object.getString("action");
                } else {
                    var m = "The valid message must have a action key";
                    err(m, outputStream);
                    continue;
                }

                if (object.has("value_type")) {
                    valueType = object.getString("value_type");
                } else {
                    var m = "The valid message must have a type value_type";
                    err(m, outputStream);
                    continue;
                }
                if (action.equals("init_config")) {
                    if (!valueType.equals("object")) {
                        err("init_config value must be map", outputStream);
                        continue;
                    }
                    JSONObject config = null;
                    if (object.has("value")) {
                        config = object.getJSONObject("value");
                    } else {
                        err("init_config must have the value", outputStream);
                        continue;
                    }

                    Config.getInstance().initialize(config.toString());

                } else if (action.equals("set_config")) {
                    String key = null;
                    if (object.has("key")) {
                        key = object.getString("key");
                    } else {
                        err("set_config must have the key",outputStream);
                        continue;
                    }
                    String value = null;
                    if (object.has("value")) {
                        value = object.getString("value");
                    } else {
                        err("set_config must have the value",outputStream);
                        continue;
                    }

                    Config.getInstance().setValue(key, value);
                    success(outputStream);
                } else if (action.equals("add_config")) {

                } else if (action.equals("read_config")) {
                    outputStream.write(Config.getInstance().toJsonString().getBytes());
                } else if (action.equals("get_config")) {
                    String key = null;
                    if (object.has("key")) {
                        key = object.getString("key");
                    } else {
                        err("get_config must have the key",outputStream);
                        continue;
                    }

                    String value = Config.getInstance().getValue(key);
                    outputStream.write(String.format("%s=%s",key,value).getBytes());
                } else if (action.equals("set_pocs")) {
                    if (!valueType.equals("array")) {
                        err("set_pocs value type must be array",outputStream);
                        continue;
                    }

                    JSONArray pocs = null;
                    if (object.has("value")) {
                        pocs = object.getJSONArray("value");
                    } else {
                        err("set_pocs must have the value",outputStream);
                        continue;
                    }
                    List<String> store = new ArrayList<>();
                    for (int i=0;i < pocs.length();i++) {
                        store.add(pocs.getString(i));
                    }
                    Config.getInstance().setValue("pocs.enable_pocs",String.join(",",store));
                    success(outputStream);
                } else if (action.equals("list_pocs")) {
                    var modules = getModules();
                    JSONArray array = new JSONArray();
                    for (var module : modules) {
                        array.put(to_snake_case(module));
                    }
                    outputStream.write(array.toString().getBytes());
                } else if (action.equals("list_running_pocs")) {
                    getModules();
                    var pocs = getEnableModules();
                    JSONArray array = new JSONArray(pocs);
                    outputStream.write(array.toString().getBytes());
                } else if (action.equals("add_pocs")) {
                    if (!valueType.equals("array")) {
                        err("add_pocs value type must be array",outputStream);
                        continue;
                    }

                    JSONArray pocs = null;
                    if (object.has("value")) {
                        pocs = object.getJSONArray("value");
                    } else {
                        err("add_pocs must have the value",outputStream);
                        continue;
                    }
                    List<String> store = new ArrayList<>();
                    for (int i=0;i < pocs.length();i++) {
                        store.add(pocs.getString(i));
                    }
                    String newPocs = String.join(",",store);
                    String originalPocs = Config.getInstance().getValue("pocs.enable_pocs");
                    Config.getInstance().setValue("pocs.enable_pocs",originalPocs + "," + newPocs);
                    success(outputStream);
                } else if (action.equals("remove_pocs")) {

                } else if (action.equals("set_poc_info_level")) {

                } else if (action.equals("info_poc")) {

                } else if (action.equals("set_free_poc")) {

                } else if (action.equals("info_http")) {

                }
            } catch (JSONException ex) {
                try {
                    err("Not a valid json String:" + ex.getLocalizedMessage(),outputStream);
                } catch (IOException e) {
                    break;
                }
                continue;
            } catch (IOException ex) {
                break;
            }
        }
    }

}

public class ProcServer implements Runnable {
    int port;
    Logger logger;
    ServerSocket ss;
    public ProcServer(int port) {
        this.port = port;
        this.logger = Logger.getLogger(Logger.Level.Debug);
    }

    @Override
    public void run() {
        logger.info("Starting ProcServer Class...");
        ss = null;
        Socket client = null;

        try {
            ss = new ServerSocket(this.port);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        while (true) {
            try {
                client = ss.accept();
                logger.info("Got a connection from " + client.getInetAddress().toString() + ":"+client.getPort());
                var inputStream = client.getInputStream();
                var outputStream = client.getOutputStream();
                var handler = new Handler();
                handler.setStream(inputStream,outputStream);
                var t = new Thread(handler);
                t.start();
            } catch (IOException e) {
                logger.error(e.getLocalizedMessage());
            }
        }

    }

    public void close() {
        try {
            this.ss.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    static ProcServer server = null;
    public static ProcServer getInstance() {
        if (server != null) {
            return server;
        }

        server = new ProcServer(9999);
        return server;
    }
}
