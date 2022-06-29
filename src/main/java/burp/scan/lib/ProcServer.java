package burp.scan.lib;

import burp.scan.lib.utils.Config;
import burp.scan.lib.utils.Logger;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

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

    InputStream inputStream;
    OutputStream outputStream;

    public void setStream(InputStream inputStream, OutputStream outputStream) {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
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
                    var m = "The valid message must have a type key";
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
                        logger.info("set_config must have the key");
                        continue;
                    }
                    String value = null;
                    if (object.has("value")) {
                        value = object.getString("value");
                    } else {
                        logger.info("set_config must have the value");
                        continue;
                    }

                    Config.getInstance().setValue(key, value);
                } else if (action.equals("add_config")) {

                } else if (action.equals("read_config")) {

                } else if (action.equals("get_config")) {

                } else if (action.equals("set_pocs")) {

                } else if (action.equals("list_pocs")) {
                    var m = "The valid message must have a type key";
                    err(m, outputStream);
                    continue;
                } else if (action.equals("list_running_pocs")) {

                } else if (action.equals("add_pocs")) {

                } else if (action.equals("remove_pocs")) {

                } else if (action.equals("set_poc_info_level")) {

                } else if (action.equals("info_poc")) {

                } else if (action.equals("set_free_poc")) {

                }
            } catch (JSONException ex) {
                logger.debug("Not a valid json String:" + ex.getLocalizedMessage());
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
