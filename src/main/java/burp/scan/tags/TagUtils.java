package burp.scan.tags;

import java.util.Arrays;
import java.util.HashMap;

public class TagUtils {
    public static HashMap<String,Tag> tagsTable = new HashMap<>();

    public static void InitTags() {
        for (TagTypes tagType : TagTypes.values()) {
            String typeName = tagType.name();
            if (typeName == "Base") {
                ConstructTags("Base","");
                continue;
            }
            String[] tmps = typeName.split("_");
            if (tmps.length >= 2) {
                String name = tmps[0];
                String[] parents = Arrays.copyOf(tmps,1);
                ConstructTags(name,parents);
            }
        }
    }
    static Tag ConstructTags(String name,String... parents) {
        Tag tag = new Tag(name);
        tag.SetParents(parents);
        TagUtils.tagsTable.put(name,tag);
        return tag;
    }

    static Tag GetTag(String name) {
        return tagsTable.get(name);
    }
}
