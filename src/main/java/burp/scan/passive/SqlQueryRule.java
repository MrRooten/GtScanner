package burp.scan.passive;


import burp.*;
import burp.scan.lib.Risk;
import burp.scan.lib.WebInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SqlQueryRule implements PassiveRule {


    private static final List<Pattern> SQL_QUERIES_RE = new ArrayList();
    static {
        SQL_QUERIES_RE.add(Pattern.compile("select ", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
        SQL_QUERIES_RE.add(Pattern.compile("IS NOT NULL", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader,
                     WebInfo webInfo) {

        IExtensionHelpers helpers = callbacks.getHelpers();

        /**
         * SQL statements in URL
         *
         * Improved detection for SQL statements in HTTP POST requests.
         */
        if (reqBody != null) {

            // check the pattern on response reqBody
            for (Pattern sqlQueryRule : SQL_QUERIES_RE) {

                Matcher matcher = sqlQueryRule.matcher(helpers.urlDecode(reqBody));

                if (matcher.find()) {
                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            baseRequestResponse,
                            "SQL Statements in HTTP Request",
                            "J2EEScan potentially identified SQL statements in HTTP POST requests.<br />"
                                    + "If SQL queries are passed from client to server in HTTP requests, a malicious user "
                                    + "could be able to alter the SQL statement executed on the remote database.",
                            "Analyse the issue and modify the application behaviour, removing the SQL queries from the HTTP requests.",
                            Risk.Medium,
                            Confidence.Tentative
                    ));
                }
            }
        }
    }
}
