package burp.scan.active.poc;

import burp.*;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.Disable;
import burp.scan.active.feature.RunOnce;
import burp.scan.active.feature.risk.HighRisk;
import burp.scan.lib.*;
import burp.scan.lib.web.WebPageInfo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.util.*;

public class AJPDetector implements ModuleBase, RunOnce, HighRisk, Disable {
    private static final String TITLE = "Apache JServ Protocol (AJP) detected";
    private static final String DESCRIPTION = "J2EEscan has identified a service using the Apache JServ Protocol (AJP), exposed via TCP port ";
    private static final String REMEDY = "This issue does not constitute a security issue by itself. However, a misconfigured"
            + " AJP proxy may allow unauthorized access to internal resources. Disable AJP, if not used.";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;
    private static final int[] AJP13PORTS = {8080, 8102, 8081, 6800, 6802, 8009, 8109, 8209, 8309, 8888, 9999};
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {
        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        IHttpRequestResponse baseRequestResponse = webInfo.getHttpRequestResponse();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();

        for (int port : AJP13PORTS) {
            String system = host.concat(Integer.toString(port));

            // System not yet tested for this vulnerability
            if (!hs.contains(system)) {

                hs.add(system);

                //Send a CPing using a raw TCP socket
                byte[] CPing = new byte[]{
                        (byte) 0x12, (byte) 0x34, (byte) 0x00, (byte) 0x01, (byte) 0x0a};

                //Retrieve CPong
                byte[] CPong = null;
                try {
                    CPong = sendData(host, port, CPing);
                } catch (IOException ex) {
                    stderr.println("[!] AJPDetector Socket error: " + host + ":" + port);
                }

                if (CPong != null && getHex(CPong).equalsIgnoreCase("414200010900000000")) {
                    try {
                        //AJP detected
                        issues.add(new GtScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(url.getProtocol(), url.getHost(), port, "AJP_TCP_" + port),
                                new CustomHttpRequestResponse(CPing, CPong, baseRequestResponse.getHttpService()),
                                TITLE,
                                DESCRIPTION+"<b>" + port + "</b>",
                                REMEDY,
                                Risk.Information,
                                Confidence.Certain
                        ));
                    } catch (MalformedURLException ex) {
                        stderr.println("[!] MalformedURLException error...\n" + ex.getMessage());
                    }
                }
            }
        }
    }

    private static byte[] sendData(String ip, int port, byte[] data) throws IOException {

        byte[] reply = new byte[9];

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(ip, port), 2000);
        DataOutputStream os = new DataOutputStream(socket.getOutputStream());
        DataInputStream is = new DataInputStream(socket.getInputStream());
        os.write(data);
        os.flush();
        is.read(reply);
        socket.close();

        return reply;
    }

    private static String getHex(byte[] raw) {

        final String HEXES = "0123456789ABCDEF";
        if (raw == null) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }

    @Override
    public Set<String> getTags() {
        Set<String> result = new HashSet<>();
        result.add("Tomcat");
        return result;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
