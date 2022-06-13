package burp.scan.lib;

import burp.IParameter;
import burp.IRequestInfo;

import java.util.ArrayList;
import java.util.List;

public class RequestInfoParser {
    IRequestInfo info;
    byte[] request;
    List<GtParameter> parameters = new ArrayList<>();
    public RequestInfoParser(IRequestInfo requestInfo) {
        info = requestInfo;

    }

    public List<GtParameter> getParameters() {
        if (this.parameters.size() != 0) {
            return this.parameters;
        }
        List<IParameter> parameters = this.info.getParameters();
        for (var parameter : parameters) {
            this.parameters.add(new GtParameter(parameter));
        }
        return this.parameters;
    }

}
