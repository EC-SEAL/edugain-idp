/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.model.pojo;

import javax.validation.constraints.NotBlank;

/**
 *
 * @author nikos
 */
public class AmkaForm {

    @NotBlank(message="AMKA must not be empty")
    public String amkaNumber;
    public String academicId;
    public String sessionId;
    
    @NotBlank(message="Please select a university")
    public String code;

    public AmkaForm() {
    }

    public AmkaForm(String amka, String academicId, String sessionId, String code
    ) {
        this.amkaNumber = amka;
        this.academicId = academicId;
        this.sessionId = sessionId;
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getAmkaNumber() {
        return amkaNumber;
    }

    public void setAmkaNumber(String amkaNumber) {
        this.amkaNumber = amkaNumber;
    }

    public String getAcademicId() {
        return academicId;
    }

    public void setAcademicId(String academicId) {
        this.academicId = academicId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

}
