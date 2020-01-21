/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as;

import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

/**
 *
 * @author nikos
 */
public class SamlWithRelayStateEntryPoint extends SAMLEntryPoint {

    @Override
    protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) {

        WebSSOProfileOptions ssoProfileOptions;
        if (defaultOptions != null) {
            ssoProfileOptions = defaultOptions.clone();
        } else {
            ssoProfileOptions = new WebSSOProfileOptions();
        }

        //Do some stuff with the context parameter
        //You can get the request from context and extract some parameters
        HttpServletRequestAdapter httpServletRequestAdapter = (HttpServletRequestAdapter) context.getInboundMessageTransport();

        String apSession = httpServletRequestAdapter.getParameterValue("session");

        if (apSession != null) {
        	log.info("Bitconnect!");
            ssoProfileOptions.setRelayState("/grap/saml/ap/samlSuccess?session=" + apSession);
        }

        return ssoProfileOptions;
    }
}
