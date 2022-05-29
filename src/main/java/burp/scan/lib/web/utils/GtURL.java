package burp.scan.lib.web.utils;

import java.net.MalformedURLException;

public class GtURL {
    private String url;
    private java.net.URL _u;
    public GtURL(String url) {
        this.url = url;
        try {
            this._u = new java.net.URL(url);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    public String getHost() {
        return this._u.getHost();
    }

    public Integer getPort() {
        return this._u.getPort();
    }

    public String getProtocol() {
        return this._u.getProtocol();
    }

    public String getUrl() {
        return this.url;
    }

    public String getPath() {
        return this._u.getPath();
    }

    public String getQuery() {
        return this._u.getQuery();
    }

    public String getBaseUrl() {
        return this._u.getProtocol() + "://" + this._u.getHost() + "/";
    }

    public String getFileDir() {
        if (this.url.endsWith("/")) {
            return this.url;
        }

        int lastSlash = this.url.lastIndexOf("/");
        return this.url.substring(0,lastSlash+1);
    }

    public String getFile() {
        return this._u.getFile();
    }

    public java.net.URL getURL() {
        return this._u;
    }
}
