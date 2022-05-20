
package burp.scan.lib;


public enum Risk {
    
    High("High"), Medium("Medium"), Low("Low"), Information("Information");
    private String risk;
    
    private Risk(String risk){
        this.risk = risk;
        
    }
}
