package eu.seal.idp.service.impl;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import eu.seal.idp.model.pojo.AttributeType;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {
	
	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);
	
	public Object loadUserBySAML(SAMLCredential credential)
			throws UsernameNotFoundException {
		
		
		String userID = credential.getNameID().getValue();
		
		List<Attribute> attributesList = new ArrayList<Attribute> ();
		attributesList = credential.getAttributes();
		
		for (Attribute att: attributesList) {
			AttributeType attributeType = new AttributeType();
			attributeType.setName(att.getName());
			attributeType.setFriendlyName(att.getFriendlyName());
			
		}
		
		LOG.info(userID + " is logged in");
		
		
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		authorities.add(authority);

		return new User(userID, "", true, true, true, true, authorities);
	}

	
}
