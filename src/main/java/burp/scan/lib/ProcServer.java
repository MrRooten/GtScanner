package burp.scan.lib;

import burp.scan.active.ModuleBase;
import burp.scan.lib.utils.Config;
import burp.scan.lib.utils.Logger;
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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
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
                logger.debug("Receive message: " + msg);
                JSONObject object = new JSONObject(msg);
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
                    outputStream.write(value.getBytes());
                } else if (action.equals("set_pocs")) {

                } else if (action.equals("list_pocs")) {
                    var modules = getModules();
                    JSONArray array = new JSONArray();
                    for (var module : modules) {
                        array.put(to_snake_case(module));
                    }
                    outputStream.write(array.toString().getBytes());
                } else if (action.equals("list_running_pocs")) {

                } else if (action.equals("add_pocs")) {

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
    public ProcServer(int port) {
        this.port = port;
        this.logger = Logger.getLogger(Logger.Level.Debug);
    }

    @Override
    public void run() {
        logger.info("Starting ProcServer Class...");
        ServerSocket ss = null;
        Socket client = null;

        try {
            ss = new ServerSocket(this.port);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        while (true) {
            try {
                client = ss.accept();
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
}
