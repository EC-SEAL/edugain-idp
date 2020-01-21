package eu.seal.as.model.pojo;

import java.util.Objects;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.validation.annotation.Validated;
import javax.validation.Valid;
import javax.validation.constraints.*;

/**
 * Object representing a generic identity data set, retrieved from some source and stored on a user store.
 */
@Validated

public class DataSet   {
  @JsonProperty("id")
  private String id = null;

  @JsonProperty("type")
  private String type = null;

  @JsonProperty("categories")
  @Valid
  private List<String> categories = null;

  @JsonProperty("issuerId")
  private String issuerId = null;

  @JsonProperty("subjectId")
  private String subjectId = null;

  @JsonProperty("loa")
  private String loa = null;

  @JsonProperty("issued")
  private String issued = null;

  @JsonProperty("expiration")
  private String expiration = null;

  @JsonProperty("attributes")
  @Valid
  private List<AttributeType> attributes = null;

  @JsonProperty("properties")
  @Valid
  private Map<String, String> properties = null;

  public DataSet id(String id) {
    this.id = id;
    return this;
  }

  /**
   * Unique identifier of the set
   * @return id
  **/

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public DataSet type(String type) {
    this.type = type;
    return this;
  }

  /**
   * To define different kinds of datasets, to establish classifications
   * @return type
  **/


  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public DataSet categories(List<String> categories) {
    this.categories = categories;
    return this;
  }

  public DataSet addCategoriesItem(String categoriesItem) {
    if (this.categories == null) {
      this.categories = new ArrayList<String>();
    }
    this.categories.add(categoriesItem);
    return this;
  }

  /**
   * To define multiple classes where the data set can be grouped.
   * @return categories
  **/


  public List<String> getCategories() {
    return categories;
  }

  public void setCategories(List<String> categories) {
    this.categories = categories;
  }

  public DataSet issuerId(String issuerId) {
    this.issuerId = issuerId;
    return this;
  }

  /**
   * Name of the attribute that is the ID of the entity that issued the data set, a kind of pointer to the property ID.
   * @return issuerId
  **/


  public String getIssuerId() {
    return issuerId;
  }

  public void setIssuerId(String issuerId) {
    this.issuerId = issuerId;
  }

  public DataSet subjectId(String subjectId) {
    this.subjectId = subjectId;
    return this;
  }

  /**
   * Name of the attribute that is the ID of the data owner, a kind of pointer to the attribute ID.
   * @return subjectId
  **/


  public String getSubjectId() {
    return subjectId;
  }

  public void setSubjectId(String subjectId) {
    this.subjectId = subjectId;
  }

  public DataSet loa(String loa) {
    this.loa = loa;
    return this;
  }

  /**
   * Level of assurance of the authenticity of the data/authentication
   * @return loa
  **/


  public String getLoa() {
    return loa;
  }

  public void setLoa(String loa) {
    this.loa = loa;
  }

  public DataSet issued(String issued) {
    this.issued = issued;
    return this;
  }

  /**
   * Date when the data set was retrieved from its source
   * @return issued
  **/


  public String getIssued() {
    return issued;
  }

  public void setIssued(String issued) {
    this.issued = issued;
  }

  public DataSet expiration(String expiration) {
    this.expiration = expiration;
    return this;
  }

  /**
   * Maximum validity date of the set (empty means permanent)
   * @return expiration
  **/


  public String getExpiration() {
    return expiration;
  }

  public void setExpiration(String expiration) {
    this.expiration = expiration;
  }

  public DataSet attributes(List<AttributeType> attributes) {
    this.attributes = attributes;
    return this;
  }

  public DataSet addAttributesItem(AttributeType attributesItem) {
    if (this.attributes == null) {
      this.attributes = new ArrayList<AttributeType>();
    }
    this.attributes.add(attributesItem);
    return this;
  }

  /**
   * The list of the identity attributes or claims contained on the set
   * @return attributes
  **/

  @Valid

  public List<AttributeType> getAttributes() {
    return attributes;
  }

  public void setAttributes(List<AttributeType> attributes) {
    this.attributes = attributes;
  }

  public DataSet properties(Map<String, String> properties) {
    this.properties = properties;
    return this;
  }

  public DataSet putPropertiesItem(String key, String propertiesItem) {
    if (this.properties == null) {
      this.properties = new HashMap<String, String>();
    }
    this.properties.put(key, propertiesItem);
    return this;
  }

  /**
   * Dictionary of additional fields of data related to the attributes in the set(strings only) for any specific purpose.
   * @return properties
  **/


  public Map<String, String> getProperties() {
    return properties;
  }

  public void setProperties(Map<String, String> properties) {
    this.properties = properties;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DataSet dataSet = (DataSet) o;
    return Objects.equals(this.id, dataSet.id) &&
        Objects.equals(this.type, dataSet.type) &&
        Objects.equals(this.categories, dataSet.categories) &&
        Objects.equals(this.issuerId, dataSet.issuerId) &&
        Objects.equals(this.subjectId, dataSet.subjectId) &&
        Objects.equals(this.loa, dataSet.loa) &&
        Objects.equals(this.issued, dataSet.issued) &&
        Objects.equals(this.expiration, dataSet.expiration) &&
        Objects.equals(this.attributes, dataSet.attributes) &&
        Objects.equals(this.properties, dataSet.properties);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, type, categories, issuerId, subjectId, loa, issued, expiration, attributes, properties);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DataSet {\n");
    
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
    sb.append("    categories: ").append(toIndentedString(categories)).append("\n");
    sb.append("    issuerId: ").append(toIndentedString(issuerId)).append("\n");
    sb.append("    subjectId: ").append(toIndentedString(subjectId)).append("\n");
    sb.append("    loa: ").append(toIndentedString(loa)).append("\n");
    sb.append("    issued: ").append(toIndentedString(issued)).append("\n");
    sb.append("    expiration: ").append(toIndentedString(expiration)).append("\n");
    sb.append("    attributes: ").append(toIndentedString(attributes)).append("\n");
    sb.append("    properties: ").append(toIndentedString(properties)).append("\n");
    sb.append("}");
    return sb.toString();
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

