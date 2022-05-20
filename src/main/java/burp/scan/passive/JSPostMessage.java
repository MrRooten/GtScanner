package burp.scan.passive;

import burp.*;
import burp.scan.lib.Risk;
import burp.scan.lib.WebInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JSPostMessage implements PassiveRule {

    private static final List<Pattern> POSTMESSAGE_PATTERNS = new ArrayList<>();

    static {
        POSTMESSAGE_PATTERNS.add(Pattern.compile(".addEventListener\\(\"message", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
        POSTMESSAGE_PATTERNS.add(Pattern.compile("window\\).on\\(\"message", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));
        POSTMESSAGE_PATTERNS.add(Pattern.compile(".postMessage\\(", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
            String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
            String httpServerHeader, String contentTypeResponse, String xPoweredByHeader,
                     WebInfo webInfo) {

        IExtensionHelpers helpers = callbacks.getHelpers();

        if (respBody != null && contentTypeResponse != null) {

            for (Pattern detectionRule : POSTMESSAGE_PATTERNS) {

                Matcher matcher = detectionRule.matcher(respBody);

                if (matcher.find()) {

                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            baseRequestResponse,
                            "Javascript postMessage Handler Detected",
                            "J2EEScan identified the window.postMessage() method which enables cross-origin communication between Window objects. <br />"
                                    + "postMessage specification could ignore the <i>Same Origin Policy</i><br /><br />"
                                    + "<i> [...] Any event listener used to receive messages must first check the identity "
                                    + "of the sender of the message, using the origin and possibly source properties. "
                                    + "This cannot be overstated: Failure to check the origin and possibly source properties "
                                    + "enables cross-site scripting attacks. [...]</i><br /><br />"
                                    + "Examples of vulnerable </i>postMessage</i> codes:<br />"
                                    + "<pre>"
                                    + "window.addEventListener(\"message\", function(message){console.log(message.data)});"
                                    + "</pre>"
                                    + "<br /><br />"
                                    + "<b>References</b>:<br />"
                                    + "https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage<br />"
                                    + "https://github.com/auth0/auth0.js/issues/508<br />"
                                    + "https://labs.detectify.com/2016/12/08/the-pitfalls-of-postmessage/<br />"
                                    + "https://labs.detectify.com/2017/02/28/hacking-slack-using-postmessage-and-websocket-reconnect-to-steal-your-precious-token/",
                            "If you do not expect to receive messages from other sites, do not add any event listeners for message events. "
                                    + "This is a completely foolproof way to avoid security problems.<br />" 
                                    + "If you do expect to receive messages from other sites, always verify the sender's identity using the origin "
                                    + "and possibly source properties. <br />"
                                    + "Any window (including, for example, http://evil.example.com) can send a message to any other window, and you have no guarantees that "
                                    + "an unknown sender will not send malicious messages. "
                                    + "Having verified identity, however, you still should always verify the syntax of the received message. Otherwise, a security hole in "
                                    + "the site you trusted to send only trusted messages could then open a cross-site scripting hole in your site.<br />"
                                    + "Always specify an exact target origin, not *, when you use postMessage to send data to other windows. A malicious site can change the location of the "
                                            + "window without your knowledge, and therefore it can intercept the data sent using postMessage.",
                            Risk.Information,
                            Confidence.Firm
                    ));
                }
            }

        }
    }
}