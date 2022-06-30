package burp.scan.active.poc;

import burp.IBurpExtenderCallbacks;
import burp.scan.active.ModuleBase;
import burp.scan.active.ModuleMeta;
import burp.scan.active.feature.risk.NormalRisk;
import burp.scan.lib.web.WebPageInfo;

import java.util.Set;

public class SimpleLocalFileInclude implements ModuleBase, NormalRisk {
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, WebPageInfo webInfo) {

    }

    @Override
    public Set<String> getTags() {
        return null;
    }

    @Override
    public ModuleMeta getMetadata() {
        return null;
    }
}
