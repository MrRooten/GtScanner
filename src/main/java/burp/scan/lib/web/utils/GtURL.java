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

    public String getHostNormal() {
        String result = "";
        if (this.isHttps() && this.getPort() == 443) {
            result = this._u.getHost();
        } else if (!this.isHttps() && this.getPort() == 80) {
            result = this._u.getHost();
        } else {
            result = this._u.getHost() + ":" + this._u.getPort();
        }

        return result;
    }

    public String getHost() {
        return this._u.getHost() + ":"+this.getPort();
    }

    public String getHostWithoutPort() {
        return this._u.getHost();
    }
    public Integer getPort() {
        int port = this._u.getPort();
        if (port != -1) {
            return port;
        }

        if (this._u.getProtocol().equals("https")) {
            return 443;
        }

        return 80;
    }

    public String getProtocol() {
        return this.url.substring(0,this.url.indexOf(":"));
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
        int queryMark = this.url.indexOf("?");
        String url = null;
        if (queryMark == -1) {
            url = this.url;
        } else {
            url = this.url.substring(0, this.url.indexOf("?"));
        }
        if (url.endsWith("/")) {
            return this.url;
        }

        int lastSlash = url.lastIndexOf("/");
        return url.substring(0,lastSlash+1);
    }

    public String getUrlWithoutQuery() {
        return this.url.substring(0,this.url.indexOf("?"));
    }

    public String getFile() {
        return this._u.getFile();
    }

    public java.net.URL getURL() {
        return this._u;
    }

    public boolean isHttps() {
        if (this.getProtocol().equalsIgnoreCase("https")) {
            return true;
        }

        return false;
    }
}
