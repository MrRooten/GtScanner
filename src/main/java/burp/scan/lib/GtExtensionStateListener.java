package burp.scan.lib;

import burp.IExtensionStateListener;

public class GtExtensionStateListener implements IExtensionStateListener {
    @Override
    public void extensionUnloaded() {
        ProcServer.getInstance().close();
    }
}
