package eu.seal.idp.service.impl;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

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
	
	
	public String getUniqueIdFromCredentials (SAMLCredential credential) {
		
		String uniqueId= "urn:mace:project-seal.eu:id:edugain-idp";
		String auxIssuer = "";
		String auxSubject = "";
		
		// The issuer of the identity, which can be, in this order: 			 
		//	schacHomeOrganization
		//	o   (from eduPerson)
		//	eduPersonOrgDN 
		//	"default-issuer"

		// The subject identifier, which can be, in this order :
		// schacPersonalUniqueID, schacPersonalUniqueCode, eduPersonTargetedID, eduPersonPrincipalName, "default-subject"				
		List<Attribute> attributesList = credential.getAttributes();
		for (Attribute att: attributesList) {
			if ((att.getFriendlyName() != null) && (
				(att.getFriendlyName().contains ("schacHomeOrganization")) ||
				(att.getFriendlyName().contains ("eduPersonOrgDN")) 
					)) {
				auxIssuer = getAttributeValuesFromCredential(att.getAttributeValues())[0];
				break;
			}		
		}
		
		for (Attribute att: attributesList) {
			if ((att.getFriendlyName() != null) && (
				(att.getFriendlyName().contains ("schacPersonalUniqueID")) ||
				(att.getFriendlyName().contains ("schacPersonalUniqueCode")) ||
				(att.getFriendlyName().contains ("eduPersonTargetedID")) ||
				(att.getFriendlyName().contains ("eduPersonPrincipalName")) 
					)) {
				auxSubject = getAttributeValuesFromCredential(att.getAttributeValues())[0];
				break;
			}		
		}
		
		if (auxIssuer.length() == 0)
			auxIssuer = "default-issuer";
		if (auxSubject.length() == 0)
			auxSubject = "default-subject";
		
		uniqueId = uniqueId + ":" + auxIssuer + ":" + auxSubject;
		
		LOG.info("uniqueId: " + uniqueId);
		
		//return (DigestUtils.sha1Hex(uniqueId));  // TODO
		return (uniqueId);
				
	}
	
	public DataSet loadDatasetBySAML(String dsId, SAMLCredential credential)
			throws UsernameNotFoundException {
		
		//dataSet.setLoa(user.getLoa()); To be set 
        //dataSet.setIssued(id);
		//String id = "DATASET" + UUID.randomUUID().toString();	
		String id = dsId;
		SimpleDateFormat formatter = new SimpleDateFormat("EEE, d MMM YYYY HH:mm:ss z", Locale.US);
        formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        Date date = new Date();
        String nowDate = formatter.format(date);
		DataSet dataSet = new DataSet();
		dataSet.setId(id);
        dataSet.setIssuerId("issuerEntityId");
        dataSet.setIssued(nowDate);
        dataSet.setType("eduGAIN");
        
        String subjectId = "";
        // In this order:
        // schacPersonalUniqueID, schacPersonalUniqueCode, eduPersonTargetedID, eduPersonPrincipalName, "default-subject" 
        List<Attribute> attributesList = credential.getAttributes();
		for (Attribute att: attributesList) {
			if ((att.getFriendlyName() != null) && (
				(att.getFriendlyName().contains ("schacPersonalUniqueID")) ||
				(att.getFriendlyName().contains ("schacPersonalUniqueCode")) ||
				(att.getFriendlyName().contains ("eduPersonTargetedID")) ||
				(att.getFriendlyName().contains ("eduPersonPrincipalName")) 
					)) {
				subjectId = att.getFriendlyName();
				break;
			}		
		}
		if (subjectId.length() == 0)
			subjectId = "default-subject";
        dataSet.setSubjectId(subjectId);
        LOG.info("subjectId: " + subjectId);

        AttributeType issuerAttr = new AttributeType();
		issuerAttr.setName("issuerEntityId");
		issuerAttr.setFriendlyName("issuerEntityId");
		
		boolean found = false;
		for (Attribute att: attributesList) {
			AttributeType attributeType = new AttributeType();
			attributeType.setName(att.getName());
			attributeType.setFriendlyName(att.getFriendlyName());
			attributeType.setValues(getAttributeValuesFromCredential(att.getAttributeValues()));
			dataSet.addAttributesItem(attributeType);
			
			LOG.info("att.getName():" + att.getName());
			LOG.info("att.getFriendlyName():" + att.getFriendlyName());
			
			// Looking for the issuer
			if (!found && att.getName().contentEquals("issuer")) {
				found = true;
				issuerAttr.setValues(getAttributeValuesFromCredential(att.getAttributeValues()));
			}
		}
		
		dataSet.addAttributesItem(issuerAttr);
		
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
			attributeType.setValues(getAttributeValuesFromCredential(att.getAttributeValues()));
			
			attributes.add(attributeType);
		}
	    AttributeSetStatus atrSetStatus = new AttributeSetStatus();
	    atrSetStatus.setCode(AttributeSetStatus.CodeEnum.OK);
	    
		AttributeSet attrSet = new AttributeSet();
		//attrSet.setId("ANOTHER_DATA_SET" + UUID.randomUUID().toString());
		attrSet.setId(dsId);
		attrSet.setType(TypeEnum.RESPONSE);
		attrSet.setIssuer(System.getenv("RESPONSE_SENDER_ID"));
		attrSet.setRecipient(System.getenv("CL_RESPONSE_RECEIVER_ID"));
		attrSet.setInResponseTo(inResponseTo);
		attrSet.setNotBefore("");
		attrSet.setNotAfter("");
		attrSet.setStatus(atrSetStatus);
		attrSet.setAttributes(attributes);
		
		
		
		LOG.info("HEY: " + attrSet.toString());
		return attrSet;
	}
	
	
	public String[] getAttributeValuesFromCredential(List<XMLObject> input) {
		//String[] result;
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
