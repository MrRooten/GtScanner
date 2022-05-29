package burp.scan.lib.web.utils;

public class GtResponse {
    byte[] responseBytes;
    GtRequest request;
    Exception exception;
    public byte[] getResponse() {
        return null;
    }

    public GtRequest getRequest() {
        return null;
    }

    public void setException(Exception e) {
        this.exception = e;
    }
}
