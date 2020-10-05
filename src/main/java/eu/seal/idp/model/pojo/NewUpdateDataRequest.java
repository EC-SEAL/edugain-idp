

package eu.seal.idp.model.pojo;


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

//import lombok.AllArgsConstructor;
//import lombok.Getter;
//import lombok.NoArgsConstructor;
//import lombok.Setter;
//
//
//@NoArgsConstructor
//@AllArgsConstructor
//@Getter
//@Setter
public class NewUpdateDataRequest {

    private String sessionId;
    private String type;
    private String data;
    private String id;
	public void setId(String objectId) {
		this.id = objectId;
	}
	
	public void setType(String type) {
		this.type = type;
	}
	
	public void setData(String data) {
		this.data = data;
	}
	
	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}
	
	public String getId() {
		return id;
	}
	
	public String getType() {
		return type;
	}
	
	public String getData() {
		return data;
	}
	
	public String getSessionId() {
		return sessionId;
	}

}