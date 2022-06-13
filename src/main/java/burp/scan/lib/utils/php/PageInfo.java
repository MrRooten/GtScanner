package burp.scan.lib.utils.php;

public class PageInfo {
    String respBody = null;
    public PageInfo(String respBody) {
        this.respBody = respBody;
    }

    public boolean isPHPInfo() {
        if (this.respBody.contains("Zend Extension Build")) {
            return true;
        }

        return false;
    }
}
