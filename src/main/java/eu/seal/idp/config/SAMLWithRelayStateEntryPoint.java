package eu.seal.idp.config;

import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.web.server.ResponseStatusException;

import eu.seal.idp.controllers.AuthenticateController;



public class SAMLWithRelayStateEntryPoint extends SAMLEntryPoint {

    @Override
    protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) {

    	final Logger LOG = LoggerFactory.getLogger(SAMLWithRelayStateEntryPoint.class);
        WebSSOProfileOptions ssoProfileOptions;
        if (defaultOptions != null) {
            ssoProfileOptions = defaultOptions.clone();
        } else {
            ssoProfileOptions = new WebSSOProfileOptions();
        }
        HttpServletRequestAdapter httpServletRequestAdapter = (HttpServletRequestAdapter) context.getInboundMessageTransport();
        String session = httpServletRequestAdapter.getParameterValue("session");
        String callback = httpServletRequestAdapter.getParameterValue("callback");
        LOG.info("*** SAMLWithRelayStateEntryPoint: Session: " + session + "\n" );
        LOG.info("*** SAMLWithRelayStateEntryPoint: Callback: " + session + "\n" );
        if(session!=null && !session.isEmpty()) {
        	System.out.println("Received session = " + session + "Received callback" + callback);
            ssoProfileOptions.setRelayState(callback + "?session=" + session);
        }
        else {
          throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad request: " + "SessionID null");
        }
        return ssoProfileOptions;
    }
}
