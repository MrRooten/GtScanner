
package burp.scan.lib;


import org.apache.coyote.ajp.Constants;

import javax.net.SocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Arrays;

/**
 * 
 *  https://github.com/threedr3am/learnjavabug/tree/master/tomcat/ajp-bug/src/main/java/com/threedr3am/bug/tomcat/ajp
 * 
 * AJP client that is not (yet) a full AJP client implementation as it just
 * provides the functionality required for the unit tests. The client uses
 * blocking IO throughout.
 */
public class SimpleAjpClient {

    private static final int AJP_PACKET_SIZE = 8192;
    private static final byte[] AJP_CPING;

    static {
        TesterAjpMessage ajpCping = new TesterAjpMessage(16);
        ajpCping.reset();
        ajpCping.appendByte(Constants.JK_AJP13_CPING_REQUEST);
        ajpCping.end();
        AJP_CPING = new byte[ajpCping.getLen()];
        System.arraycopy(ajpCping.getBuffer(), 0, AJP_CPING, 0,
                ajpCping.getLen());
    }

    private String host = "localhost";
    private int port = -1;
    private Socket socket = null;

    public int getPort() {
        return port;
    }

    public void connect(String host, int port) throws IOException {
        this.host = host;
        this.port = port;
        socket = SocketFactory.getDefault().createSocket(host, port);
        socket.setSoTimeout(6000);
    }

    public void disconnect() throws IOException {
        socket.close();
        socket = null;
    }

    /**
     * Create a message to request the given URL.
     */
    public TesterAjpMessage createForwardMessage(String url) {
        return createForwardMessage(url, 2);
    }

    public TesterAjpMessage createForwardMessage(String url, int method) {

        TesterAjpMessage message = new TesterAjpMessage(AJP_PACKET_SIZE);
        message.reset();

        // Set the header bytes
        message.getBuffer()[0] = 0x12;
        message.getBuffer()[1] = 0x34;

        // Code 2 for forward request
        message.appendByte(Constants.JK_AJP13_FORWARD_REQUEST);

        // HTTP method, GET = 2
        message.appendByte(method);

        // Protocol
        message.appendString("http/1.1");

        // Request URI
        message.appendString(url);

        // Remote address
        message.appendString("127.0.0.1");

        // Remote host
        message.appendString("localhost");

        // Server name
        message.appendString(host);

        // Port
        message.appendInt(port);

        // Is ssl
        message.appendByte(0x00);

        return message;
    }


    public TesterAjpMessage createBodyMessage(byte[] data) {

        TesterAjpMessage message = new TesterAjpMessage(AJP_PACKET_SIZE);
        message.reset();

        // Set the header bytes
        message.getBuffer()[0] = 0x12;
        message.getBuffer()[1] = 0x34;

        message.appendBytes(data, 0, data.length);
        message.end();

        return message;
    }


    /**
     * Sends an TesterAjpMessage to the server and returns the response message.
     */
    public void sendMessage(TesterAjpMessage headers)
            throws IOException {
        sendMessage(headers, null);
    }

    public void sendMessage(TesterAjpMessage headers,
            TesterAjpMessage body) throws IOException {
        // Send the headers
        socket.getOutputStream().write(
                headers.getBuffer(), 0, headers.getLen());
        if (body != null) {
            // Send the body of present
            socket.getOutputStream().write(
                    body.getBuffer(), 0, body.getLen());
        }
    }
    /**
     * Reads a message from the server.
     */
    public byte[] readMessage() throws IOException {

        InputStream is = socket.getInputStream();

        TesterAjpMessage message = new TesterAjpMessage(AJP_PACKET_SIZE);

        byte[] buf = message.getBuffer();
        int headerLength = message.getHeaderLength();

        read(is, buf, 0, headerLength);

        int messageLength = message.processHeader(false);
        if (messageLength < 0) {
            throw new IOException("Invalid AJP message length");
        } else if (messageLength == 0) {
            return null;
        } else {
            if (messageLength > buf.length) {
                throw new IllegalArgumentException("Message too long [" +
                        Integer.valueOf(messageLength) +
                        "] for buffer length [" +
                        Integer.valueOf(buf.length) + "]");
            }
            read(is, buf, headerLength, messageLength);
            return Arrays.copyOfRange(buf, headerLength, headerLength + messageLength);
        }
    }

    protected boolean read(InputStream is, byte[] buf, int pos, int n)
        throws IOException {

        int read = 0;
        int res = 0;
        while (read < n) {
            res = is.read(buf, read + pos, n - read);
            if (res > 0) {
                read += res;
            } else {
                throw new IOException("Read failed");
            }
        }
        return true;
    }
}