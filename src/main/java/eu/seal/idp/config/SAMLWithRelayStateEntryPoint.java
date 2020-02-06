package eu.seal.idp.config;

import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileOptions;



public class SAMLWithRelayStateEntryPoint extends SAMLEntryPoint {

    @Override
    protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) {

        WebSSOProfileOptions ssoProfileOptions;
        if (defaultOptions != null) {
            ssoProfileOptions = defaultOptions.clone();
        } else {
            ssoProfileOptions = new WebSSOProfileOptions();
        }
        HttpServletRequestAdapter httpServletRequestAdapter = (HttpServletRequestAdapter) context.getInboundMessageTransport();
        String session = httpServletRequestAdapter.getParameterValue("session");
        

        if (session != null) {
            ssoProfileOptions.setRelayState("/as/callback?session=" + session);
        }
        
        return ssoProfileOptions;
    }
}
