package eu.seal.idp.model.pojo;


public class AttributeType {
    
    private String name;
    private String friendlyName;
    private String encoding;
    private String language;
    private boolean mandatory;
    private String[] values;
    
    

    public AttributeType() {
    }

    public AttributeType(String name, String friendlyName, String encoding, String language, boolean mandatory, String[] values) {
        this.name = name;
        this.friendlyName = friendlyName;
        this.encoding = encoding;
        this.language = language;
        this.mandatory = mandatory;
        this.values = values;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getFriendlyName() {
        return friendlyName;
    }

    public void setFriendlyName(String friendlyName) {
        this.friendlyName = friendlyName;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public boolean mandatory() {
        return mandatory;
    }

    public void setMandatory(boolean mandatory) {
        this.mandatory = mandatory;
    }

    public String[] getValues() {
        return values;
    }

    public void setValues(String[] values) {
        this.values = values;
    }

    @Override
    public String toString() {
    	  StringBuilder sb = new StringBuilder();
    	    sb.append("class AttributeType {\n");
    	    
    	    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    	    sb.append("    friendlyName: ").append(toIndentedString(friendlyName)).append("\n");
    	    sb.append("    encoding: ").append(toIndentedString(encoding)).append("\n");
    	    sb.append("    language: ").append(toIndentedString(language)).append("\n");
    	    sb.append("    mandatory: ").append(toIndentedString(mandatory)).append("\n");
    	    sb.append("    values: ").append(toIndentedString(values)).append("\n");
    	    sb.append("}");
    	    return sb.toString();
       // return "AttributeType{" + "name=" + name + ", friendlyName=" + friendlyName + ", encoding=" + encoding + ", language=" + language + ", mandatory=" + mandatory + ", values=" + values.toString() + '}';
    }
    
    /**
     * Convert the given object to string with each line indented by 4 spaces
     * (except the first line).
     */
    private String toIndentedString(java.lang.Object o) {
      if (o == null) {
        return "null";
      }
      return o.toString().replace("\n", "\n    ");
    }
    
}
