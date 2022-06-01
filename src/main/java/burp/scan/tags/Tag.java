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

    public Set<String> getParents() {
        return this.parents;
    }
    void help(Set<String> save,Set<String> currents) {
        if (currents.contains("Base")) {
            return ;
        }
        save.addAll(currents);
        for (var current : currents) {
            var parents = TagUtils.GetTag(current).getParents();
            help(save,parents);
        }
    }
    public Set<String> GetAncestors() {
        Set<String> save = new HashSet<>();
        help(save,this.parents);
        save.add("Base");
        return save;
    }
}
