package burp.scan.passive;

import burp.*;
import burp.scan.lib.Confidence;
import burp.scan.lib.GtScanIssue;
import burp.scan.lib.PassiveRule;
import burp.scan.lib.Risk;
import burp.scan.lib.web.WebPageInfo;
import burp.scan.tags.TagTypes;

public class GitLabRule implements PassiveRule {
    Confidence levelGitLab(String respBody) {
        if (respBody.contains("<a href=\"https://about.gitlab.com/\">about gitlab") ||
        respBody.contains("class=\"col-sm-7 brand-holder pull-left\"")||
        respBody.contains("gon.default_issues_tracker")||
        respBody.contains("content=\"gitlab community edition\"")||
        respBody.contains("'content=\"gitlab '")) {
            return Confidence.Certain;
        }

        return null;
    }

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo, String httpServerHeader, String contentTypeResponse, String xPoweredByHeader, WebPageInfo webPageInfo) {
        if (levelGitLab(respBody)!=null) {
            IScanIssue issue = new GtScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    baseRequestResponse,
                    "Gitlab Fingerprint",
                    "May have CVE-2021-22205",
                    "",
                    Risk.Information,
                    Confidence.Certain
            );
            callbacks.addScanIssue(issue);
            webPageInfo.addIssue(issue);
            webPageInfo.addTag(TagTypes.Gogs_Golang);
        }
    }
}
