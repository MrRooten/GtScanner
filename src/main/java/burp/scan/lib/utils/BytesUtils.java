package burp.scan.lib.utils;

public class BytesUtils {
    public static byte[] replaceBytes(byte[] src,byte[] toReplace,int start,int end) {
        byte[] res = new byte[src.length - (end - start) + toReplace.length];
        System.arraycopy(src,0,res,0, start);
        System.arraycopy(toReplace,0,res,start,toReplace.length);
        System.arraycopy(src,end,res,start + toReplace.length,src.length-end);
        return res;
    }
}
