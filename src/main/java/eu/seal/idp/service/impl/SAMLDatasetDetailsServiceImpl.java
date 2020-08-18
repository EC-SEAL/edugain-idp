package eu.seal.idp.service.impl;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Service;


import eu.seal.idp.model.pojo.AttributeSet;
import eu.seal.idp.model.pojo.AttributeSet.TypeEnum;
import eu.seal.idp.model.pojo.AttributeSetStatus;
import eu.seal.idp.model.pojo.AttributeType;
import eu.seal.idp.model.pojo.DataSet;

@Service
public class SAMLDatasetDetailsServiceImpl {
	
	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(SAMLDatasetDetailsServiceImpl.class);
	
	public DataSet loadDatasetBySAML(String dsId, SAMLCredential credential)
			throws UsernameNotFoundException {
		
		//dataSet.setLoa(user.getLoa()); To be set 
        //dataSet.setIssued(id);
		String id = UUID.randomUUID().toString();	
		SimpleDateFormat formatter = new SimpleDateFormat("EEE, d MMM YYYY HH:mm:ss z", Locale.US);
        formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        Date date = new Date();
        String nowDate = formatter.format(date);
		DataSet dataSet = new DataSet();
		dataSet.setId(id);
        dataSet.setIssuerId("This is the user ID.");
        dataSet.setIssued(nowDate);
        dataSet.setType("eduGAIN");

		
		List<Attribute> attributesList = credential.getAttributes();
		
		for (Attribute att: attributesList) {
			AttributeType attributeType = new AttributeType();
			LOG.info("*****_Name" + att.getName());
			attributeType.setName(att.getName());
			attributeType.setFriendlyName(att.getFriendlyName());
			attributeType.setValues(getAttributeValuesFromCredential(att.getAttributeValues()));
			LOG.info("*****_FriendlyName" + att.getName());
			dataSet.addAttributesItem(attributeType);
		}
		
		LOG.info(dataSet.toString());
		return dataSet;
	}
	
	public AttributeSet loadAttributeSetBySAML(String dsId, String inResponseTo, SAMLCredential credential)
			throws UsernameNotFoundException {
		

		List <AttributeType> attributes = new ArrayList();
		AttributeType[] attributeTypeArray = new AttributeType[attributes.size()];
		List<Attribute> attributesList = credential.getAttributes();
		
		for (Attribute att: attributesList) {
			AttributeType attributeType = new AttributeType();
			attributeType.setName(att.getName());
			attributeType.setFriendlyName(att.getFriendlyName());
			attributes.add(attributeType);
		}
	    AttributeSetStatus atrSetStatus = new AttributeSetStatus();
	    atrSetStatus.setCode(AttributeSetStatus.CodeEnum.OK);
	    
		AttributeSet attrSet = new AttributeSet();
		attrSet.setId(UUID.randomUUID().toString());
		attrSet.setType(TypeEnum.RESPONSE);
		attrSet.setIssuer(System.getenv("RESPONSE_SENDER_ID"));
		attrSet.setRecipient(System.getenv("CL_RESPONSE_RECEIVER_ID"));
		attrSet.setInResponseTo(inResponseTo);
		attrSet.setNotBefore("");
		attrSet.setNotAfter("");
		attrSet.setStatus(atrSetStatus);
		attrSet.setAttributes(attributes);
		
		
		
		LOG.info(attrSet.toString());
		return attrSet;
	}
	
	
	public String[] getAttributeValuesFromCredential(List<XMLObject> input) {
		String[] result;
		ArrayList<String> ar = new ArrayList<String>();
		input.forEach((v)->{
			String value = getAttributeValue(v);
			ar.add(value);
		});
		String[] stringArray = ar.toArray(new String[0]);
		return stringArray;
	}
	
	private String getAttributeValue(XMLObject attributeValue)
	{
	    return attributeValue == null ?
	            null :
	            attributeValue instanceof XSString ?
	                    getStringAttributeValue((XSString) attributeValue) :
	                    attributeValue instanceof XSAnyImpl ?
	                            getAnyAttributeValue((XSAnyImpl) attributeValue) :
	                            attributeValue.toString();
	}

	private String getStringAttributeValue(XSString attributeValue)
	{
	    return attributeValue.getValue();
	}

	private String getAnyAttributeValue(XSAnyImpl attributeValue)
	{
	    return attributeValue.getTextContent();
	}
	
}
