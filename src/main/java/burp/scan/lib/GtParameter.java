package burp.scan.lib;

import burp.IParameter;

public class GtParameter {
    public enum ParameterType {
        JSON,
        URL,
        XML,
        BODY,
        COOKIE,
        MULTIPART_FORM,
        XML_ATTR,
        NOT_KNOWN
    }
    IParameter parameter;
    ParameterType type;
    public GtParameter(IParameter parameter) {
        this.parameter = parameter;
    }

    public String getName() {
        return this.parameter.getName();
    }

    public String getValue() {
        return this.parameter.getValue();
    }

    public int getNameStart() {
        return this.parameter.getNameStart();
    }

    public int getNameEnd() {
        return this.parameter.getNameEnd();
    }

    public int getValueStart() {
        return this.parameter.getValueStart();
    }

    public int getValueEnd() {
        return this.parameter.getValueEnd();
    }

    public ParameterType getType() {
        var type = this.parameter.getType();
        if (type == IParameter.PARAM_BODY) {
            return ParameterType.BODY;
        } else if (type == IParameter.PARAM_JSON) {
            return ParameterType.JSON;
        } else if (type == IParameter.PARAM_URL) {
            return ParameterType.URL;
        } else if (type == IParameter.PARAM_XML) {
            return ParameterType.XML;
        } else if (type == IParameter.PARAM_COOKIE) {
            return ParameterType.COOKIE;
        } else if (type == IParameter.PARAM_MULTIPART_ATTR) {
            return ParameterType.MULTIPART_FORM;
        } else if (type == IParameter.PARAM_XML_ATTR) {
            return ParameterType.XML_ATTR;
        }
        return ParameterType.NOT_KNOWN;
    }
}
