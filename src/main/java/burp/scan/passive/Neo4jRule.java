package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.CustomScanIssue;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;

public class Neo4jRule implements PassiveRule {
    Confidence levelNeo4j(String respBody) {
        if (respBody.contains("content=\"neo4j")) {
            return Confidence.Certain;
        }

        if (respBody.contains("ng-show=\"neo4j.enterpriseedition")) {
            return Confidence.Certain;
        }

        if (respBody.contains("play-topic=\"neo4j-sync")) {
            return Confidence.Certain;
        }

        if (respBody.contains("'{{ neo4j.version | neo4jdeveloperdoc }}/'")) {
            return Confidence.Certain;
        }

        return null;
    }
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        Confidence level = levelNeo4j(respBody);
        if (level!=null) {
            IScanIssue issue = new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Neo4j Rule",
                    "May have CVE-2021-34371:Neo4j is a graph database management system developed by Neo4j, Inc.\n" +
                            "\n" +
                            "Neo4j through 3.4.18 (with the shell server enabled) exposes an RMI service that arbitrarily deserializes Java objects, e.g., through setSessionVariable. An attacker can abuse this for remote code execution because there are dependencies with exploitable gadget chains.\n" +
                            "\n" +
                            "Neo4j Shell is replaced by Cyber Shell after Neo4j 3.5.\n" +
                            "\n" +
                            "References:\n" +
                            "\n" +
                            "https://www.exploit-db.com/exploits/50170\n" +
                            "mozilla/rhino#520",
                    "",
                    Risk.Information,
                    level
            );
            callbacks.addScanIssue(issue);
            webPageInfo.addIssue(issue);
        }
    }
}
