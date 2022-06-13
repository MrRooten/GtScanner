package burp.scan.lib.utils;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.scan.lib.web.utils.GtRequest;
import burp.scan.lib.web.utils.GtResponse;

public class GtHttpRequestResponse implements IHttpRequestResponse {
    byte[] requestMessage;
    byte[] responseMessage;
    IHttpService httpService;
    @Override
    public byte[] getRequest() {
        return this.requestMessage;
    }

    @Override
    public void setRequest(byte[] message) {
        this.requestMessage = message;
    }

    @Override
    public byte[] getResponse() {
        return this.responseMessage;
    }

    @Override
    public void setResponse(byte[] message) {
        this.responseMessage = message;
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {

    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
}
