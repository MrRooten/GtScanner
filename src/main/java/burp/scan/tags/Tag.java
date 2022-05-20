package burp.scan.tags;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

public class Tag {
    public Set<String> parents = new HashSet<>();

    public String name;

    public Tag(String name) {

    }

    public void SetParents(String... names) {
        for (String parent : names) {
            parents.add(parent);
        }
    }
    public Set<Tag> GetAncestors() {
        return null;
    }
}
