package burp.scan.active;

import burp.scan.lib.Risk;

import java.util.Map;


public class ModuleMeta {
    String author;
    String[] relateVB;
    String[] link;
    String description;
    Risk level;

    public void SetAuthor(String author) {
        this.author = author;
    }


    public void SetDescription(String description) {
        this.description = description;
    }

    public String getAuthor() {
        return this.author;
    }

    public String[] getRelateVB() {
        return this.relateVB;
    }

    public String[] getLink() {
        return this.link;
    }

    public String getDescription() {
        return this.description;
    }

    public ModuleMeta(Map<String,Object> info) {

    }
}
