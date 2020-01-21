/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service;

import eu.seal.as.exceptions.ReCaptchaInvalidException;

/**
 *
 * @author nikos
 */
public interface ICaptchaService {

    void processResponse(final String response) throws ReCaptchaInvalidException;

    String getReCaptchaSite();

    String getReCaptchaSecret();
}
