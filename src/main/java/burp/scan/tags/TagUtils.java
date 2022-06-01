package burp.scan.tags;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

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
                String[] parents = Arrays.copyOfRange(tmps,1,tmps.length);
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

    public static Tag GetTag(String name) {
        return tagsTable.get(name);
    }

    public static String toStandardName(TagTypes tagTypes) {
        String s = tagTypes.toString().split("_")[0];
        return s;
    }
}
