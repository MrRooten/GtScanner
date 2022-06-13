package burp.scan.lib.utils;

import burp.IHttpService;

public class GtHttpService implements IHttpService {
    String host;
    int port;
    String protocol;
    public GtHttpService(String host,int port,String protocol) {
        this.host = host;
        this.port = port;
        this.protocol = protocol;
    }
    @Override
    public String getHost() {
        return this.host;
    }

    @Override
    public int getPort() {
        return this.port;
    }

    @Override
    public String getProtocol() {
        return this.protocol;
    }
}
