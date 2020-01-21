/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.model.pojo;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author nikos
 */
public class EidasCurrentAddress {
    /*
    [
			{
				"LocatorDesignator"	: "string",	// 22, 1063 etc.
				"Thoroughfare"		: "string",	// Arcacia Avenue, St. Michael Street etc.
				"PostName"		    : "string",	// London, Glasgow etc.
				"PostCode"	    	: "string"	// BN3 1PH, IV27 4JQ etc.
			}
			]
    */
    @JsonProperty("LocatorDesignator")
    private String locatorDesignator;
    @JsonProperty("Thoroughfare")
    private String thoroughfare;
    @JsonProperty("PostName")
    private String postName;
    @JsonProperty("PostCode")
    private String postCode;

    public EidasCurrentAddress() {
    }

    public EidasCurrentAddress(String locatorDesignator, String thoroughfare, String postName, String postCode) {
        this.locatorDesignator = locatorDesignator;
        this.thoroughfare = thoroughfare;
        this.postName = postName;
        this.postCode = postCode;
    }

    public String getLocatorDesignator() {
        return locatorDesignator;
    }

    public void setLocatorDesignator(String locatorDesignator) {
        this.locatorDesignator = locatorDesignator;
    }

    public String getThoroughfare() {
        return thoroughfare;
    }

    public void setThoroughfare(String thoroughfare) {
        this.thoroughfare = thoroughfare;
    }

    public String getPostName() {
        return postName;
    }

    public void setPostName(String postName) {
        this.postName = postName;
    }

    public String getPostCode() {
        return postCode;
    }

    public void setPostCode(String postCode) {
        this.postCode = postCode;
    }
    
    
    
    
}
