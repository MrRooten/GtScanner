package burp.scan.lib;

import burp.IParameter;
import burp.IRequestInfo;

import java.util.ArrayList;
import java.util.List;

public class RequestParser {
    IRequestInfo info;
    List<GtParameter> parameters = new ArrayList<>();
    public RequestParser(IRequestInfo requestInfo) {
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
