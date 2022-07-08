package burp;

import burp.scan.lib.GlobalFunction;
import burp.scan.lib.GtExtensionStateListener;
import burp.scan.lib.PassiveScanner;
import burp.scan.lib.ProcServer;
import burp.scan.lib.fingerprinthub.FingerPrint;
import burp.scan.lib.utils.Config;
import burp.scan.lib.utils.Utils;
import burp.scan.tags.TagUtils;

import java.util.ArrayList;
import java.util.List;


public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // test / grep strings
    private static final byte[] INJ_TEST = "|".getBytes();
    private static final byte[] INJ_ERROR = "Unexpected pipe".getBytes();

    //
    // implement IBurpExtender
    //

    void setDefaultConfig() {
        var config = Config.getInstance();
        config.setValue("pocs.enable_pocs","*");
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        this.callbacks.registerExtensionStateListener(this);
        // set our extension name
        callbacks.setExtensionName("GtScanner");

        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
        TagUtils.InitTags();

        GlobalFunction.callbacks = callbacks;
        GlobalFunction.helpers = callbacks.getHelpers();
        FingerPrint.InitializeFingerPrints();
        try {
            var procServer = ProcServer.getInstance();
            procServer.run();
        } catch (Exception ignored) {
        }
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }

    //
    // implement IScannerCheck
    //
    static PassiveScanner scanner = new PassiveScanner();
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        // look for matches of our passive check grep string

        List<IScanIssue> issues = scanner.scanVulnerabilities(baseRequestResponse, callbacks);

        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        // make a request containing our injection test in the insertion point
        byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);

        // look for matches of our active check grep string
        List<int[]> matches = getMatches(checkRequestResponse.getResponse(), INJ_ERROR);
        if (matches.size() > 0)
        {
            // get the offsets of the payload within the request, for in-UI highlighting
            List<int[]> requestHighlights = new ArrayList<>(1);
            requestHighlights.add(insertionPoint.getPayloadOffsets(INJ_TEST));

            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);

            return issues;
        }
        else return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL
        // path by the same extension-provided check. The value we return from this
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }

    @Override
    public void extensionUnloaded() {
        ProcServer.getInstance().close();
    }
}
