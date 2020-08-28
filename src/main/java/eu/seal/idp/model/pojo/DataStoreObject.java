/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.idp.model.pojo;

import java.io.Serializable;
//import lombok.AllArgsConstructor;
//import lombok.Builder;
//import lombok.Data;
//import lombok.Getter;
//import lombok.NoArgsConstructor;
//import lombok.Setter;
//import lombok.ToString;


//@Getter
//@Setter
//@NoArgsConstructor
//@AllArgsConstructor
//@ToString
public class DataStoreObject implements Serializable {

    private String id;
    private String type;
    private String data;
    
    public String getId() {
        return id;
      }

    public void setId(String id) {
        this.id = id;
      }
    
    public String getType() {
        return type;
      }

    public void setType(String type) {
        this.type = type;
      }
    
    public String getData() {
        return data;
      }

    public void setData(String type) {
        this.type = type;
      }

}
