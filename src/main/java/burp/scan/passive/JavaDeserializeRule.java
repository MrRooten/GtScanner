package burp.scan.passive;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.web.WebPageInfo;
import org.apache.commons.lang3.ArrayUtils;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPInputStream;

import static burp.scan.lib.GlobalFunction.helpers;


public class JavaDeserializeRule implements PassiveRule {
    static private byte[] serializeMagic = new byte[]{-84, -19};
    static private byte[] base64Magic = {(byte)0x72, (byte)0x4f, (byte)0x30, (byte)0x41};
    static private byte[] asciiHexMagic = {(byte)0x61, (byte)0x63, (byte)0x65, (byte)0x64};

    static private byte[] gzipMagic = {(byte)0x1f, (byte)0x8b};
    static private byte[] base64GzipMagic = {(byte)0x48, (byte)0x34, (byte)0x73, (byte)0x49};

    static private String passiveScanIssue = "Serialized Java objects detected";
    static private String passiveScanSeverity = "Information";
    static private String passiveScanConfidence = "Firm";
    static private String passiveScanIssueDetail = "Serialized Java objects have been detected in the body"+
            " or in the parameters of the request. If the server application does "+
            " not check on the type of the received objects before"+
            " the deserialization phase, it may be vulnerable to the Java Deserialization"+
            " Vulnerability.";

    static private String remediationDetail = "<ol><li>If possible, do not use Java serialized objects and migrate to safer alternatives.</li> " +
            "<li>Keep Java software always updated and patched.</li>" +
            "<li> If is necessary to use Serialized Java Objects, "+
            " deserialize only known objects, by using custom "+
            " objects for the deserialization, insted of the Java "+
            " ObjectInputStream default one. The custom object must override the "+
            " resolveClass method, by inserting checks on the object type"+
            " before deserializing the received object. </li>" +
            " <li>Update all Java libraries used in the application, with particular attention " +
            "to the one used for the exploitation.</li></ol>";

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {

    }
}
