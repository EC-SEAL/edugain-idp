package eu.seal.idp.service.impl;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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
import org.opensaml.xml.schema.impl.XSStringImpl;
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
	
	private String moduleId;	
	
	public String getUniqueIdFromCredentials (SAMLCredential credential) {
		
		String uniqueId= "urn:mace:project-seal.eu:id:dataset:";
		try {
			moduleId = System.getenv("RESPONSE_SENDER_ID") == null ? "edugainIDPms_001": System.getenv("RESPONSE_SENDER_ID");
			uniqueId = uniqueId + //"edugain-idp";
					URLEncoder.encode(moduleId, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		String auxIssuer = null;
		String auxSubject = null;
		
		// The issuer of the identity, which can be, in this order: 			 
		//	schacHomeOrganization
		//	o   (from eduPerson)
		//	eduPersonOrgDN 
		//	"default-issuer"

		// The subject identifier, which can be, in this order :
		// schacPersonalUniqueID, schacPersonalUniqueCode, eduPersonTargetedID, eduPersonPrincipalName, "default-subject"				
		List<Attribute> attributesList = new ArrayList<Attribute> ();
		attributesList = credential.getAttributes();
		for (Attribute att: attributesList) {
			if ((att.getFriendlyName() != null) && (
				(att.getFriendlyName().contains ("schacHomeOrganization")) ||
				(att.getFriendlyName().contains ("eduPersonOrgDN")) 
					)) {
				
//				if ((getAttributeValuesFromCredential(att.getAttributeValues()) != null) &&
//						(getAttributeValuesFromCredential(att.getAttributeValues()).length > 0) &&
//						(getAttributeValuesFromCredential(att.getAttributeValues())[0] != null)) {
//					LOG.info ("friendlyName: " + att.getFriendlyName());
//					
//					auxIssuer = getAttributeValuesFromCredential(att.getAttributeValues())[0];
//					
//					break;
//				}
				
				if ((getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0)) != null) &&
						(getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0)).length > 0) &&
						(getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0))[0] != null)) {
					LOG.info ("friendlyName: " + att.getFriendlyName());
					LOG.info("valueNEW: " + getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0))[0]);
					
					auxIssuer = getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0))[0];
					
					break;
				}
			}		
		}
		
		for (Attribute att: attributesList) {
			if ((att.getFriendlyName() != null) && (
				(att.getFriendlyName().contains ("schacPersonalUniqueID")) ||
				(att.getFriendlyName().contains ("schacPersonalUniqueCode")) ||
				(att.getFriendlyName().contains ("eduPersonTargetedID")) ||
				(att.getFriendlyName().contains ("eduPersonPrincipalName")) 
					)) {
				
//				if ((getAttributeValuesFromCredential(att.getAttributeValues()) != null) &&
//						(getAttributeValuesFromCredential(att.getAttributeValues()).length > 0) &&
//						(getAttributeValuesFromCredential(att.getAttributeValues())[0] != null)) {
//					LOG.info ("friendlyName: " + att.getFriendlyName());
//					auxSubject = getAttributeValuesFromCredential(att.getAttributeValues())[0];
//					break;
//				}
				
				if ((getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0)) != null) &&
						(getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0)).length > 0) &&
						(getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0))[0] != null)) {
					LOG.info ("friendlyName: " + att.getFriendlyName());
					LOG.info("valueNEW: " + getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0))[0]);
					auxSubject = getAttributeValuesFromCredentialNEW(att.getAttributeValues().get(0))[0];
					break;
				}
			}		
		}
		
		if (auxIssuer == null || auxIssuer.length() == 0)
			//auxIssuer = "default-issuer";
			auxIssuer = credential.getRemoteEntityID();
		if (auxSubject == null || auxSubject.length() == 0)
			auxSubject = "default-subject";
		try {
			uniqueId = uniqueId + ":" + 
					URLEncoder.encode(auxIssuer, StandardCharsets.UTF_8.toString()) + ":" + 
					URLEncoder.encode(auxSubject, StandardCharsets.UTF_8.toString());
			
			LOG.info("uniqueId: " + uniqueId);
		
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//return (DigestUtils.sha1Hex(uniqueId));  // TODO?
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
        //dataSet.setIssuerId("issuerEntityId");
        dataSet.setIssued(nowDate);
        dataSet.setType("eduGAIN");
        
        
        // TODO: subjectId and auxIssuer could be read from the dsId!!!
        //
        String subjectId = "";
        // In this order:
        // schacPersonalUniqueID, schacPersonalUniqueCode, eduPersonTargetedID, eduPersonPrincipalName, "default-subject" 
        List<Attribute> attributesList = new ArrayList<Attribute> ();
		attributesList = credential.getAttributes();
		for (Attribute att: attributesList) {
			if ((att.getFriendlyName() != null) && (
				(att.getFriendlyName().contains ("schacPersonalUniqueID")) ||
				(att.getFriendlyName().contains ("schacPersonalUniqueCode")) ||
				(att.getFriendlyName().contains ("eduPersonTargetedID")) ||
				(att.getFriendlyName().contains ("eduPersonPrincipalName")) 
					)) {
				if ((getAttributeValuesFromCredential(att.getAttributeValues()) != null) &&
					(getAttributeValuesFromCredential(att.getAttributeValues()).length > 0) &&
					(getAttributeValuesFromCredential(att.getAttributeValues())[0] != null)) {
					subjectId = att.getFriendlyName();
					break;
				}
			}		
		}
		if (subjectId.length() == 0)
			subjectId = "default-subject";
        dataSet.setSubjectId(subjectId);
        LOG.info("subjectId: " + subjectId);
        
        String auxIssuer = "";
        for (Attribute att: attributesList) {
			if ((att.getFriendlyName() != null) && (
				(att.getFriendlyName().contains ("schacHomeOrganization")) ||
				(att.getFriendlyName().contains ("eduPersonOrgDN")) 
					)) {
				LOG.info ("friendlyName: " + att.getFriendlyName());
				auxIssuer = getAttributeValuesFromCredential(att.getAttributeValues())[0];
				break;
			}		
		}
        if (auxIssuer == null || auxIssuer.length() == 0)
			auxIssuer = credential.getRemoteEntityID();
        dataSet.setIssuerId(auxIssuer);
        
        AttributeType issuerAttr = new AttributeType();
		issuerAttr.setName("issuerEntityId");
		issuerAttr.setFriendlyName("issuerEntityId");
		List<String> issuerValues = new ArrayList<String>();
		issuerValues.add (auxIssuer);
		LOG.info("issuerEntityId: " + auxIssuer);
		issuerAttr.setValues(issuerValues.toArray(new String[0]));
		
		dataSet.addAttributesItem(issuerAttr);
		
		for (Attribute att: attributesList) {
			AttributeType attributeType = new AttributeType();
			attributeType.setName(att.getName());
			attributeType.setFriendlyName(att.getFriendlyName());
			attributeType.setValues(getAttributeValuesFromCredential(att.getAttributeValues()));
			dataSet.addAttributesItem(attributeType);
			
			LOG.info("att.getName():" + att.getName());
			LOG.info("att.getFriendlyName():" + att.getFriendlyName());
		}
		
//		for (AttributeStatement attributeStatement : credential.getAuthenticationAssertion().getAttributeStatements())
//	    {
//	        for (Attribute att : attributeStatement.getAttributes())
//	        {
//	        	AttributeType attributeType = new AttributeType();
//				attributeType.setName(att.getName());
//				attributeType.setFriendlyName(att.getFriendlyName());
//				//attributeType.setValues(getAttributeValuesFromCredential(att.getAttributeValues()));
//				
//				List<XMLObject> attributeValues = att.getAttributeValues();
//	            if (!attributeValues.isEmpty())
//	            {
//	                LOG.info("value: " + getAttributeValue(attributeValues.get(0)));
//	                List <String> auxL = new ArrayList<String>();
//	                auxL.add(getAttributeValue(attributeValues.get(0)));
//	                attributeType.setValues(auxL.toArray(new String[0]));
//	            }
//				dataSet.addAttributesItem(attributeType);
//	        }
//	    }
			
		LOG.info(dataSet.toString());
		return dataSet;
	}
	
	public AttributeSet loadAttributeSetBySAML(String dsId, String inResponseTo, SAMLCredential credential)
			throws UsernameNotFoundException {
		

		List <AttributeType> attributes = new ArrayList<AttributeType>();
		//AttributeType[] attributeTypeArray = new AttributeType[attributes.size()];
		List<Attribute> attributesList = new ArrayList<Attribute> ();
		attributesList = credential.getAttributes();
		
		for (Attribute att: attributesList) {
			AttributeType attributeType = new AttributeType();
			attributeType.setName(att.getName());
			attributeType.setFriendlyName(att.getFriendlyName());
			//attributeType.setValues(getAttributeValuesFromCredential(att.getAttributeValues()));
			
			List<XMLObject> attributeValues = att.getAttributeValues();
            if (!attributeValues.isEmpty())
            {
                LOG.info("value: " + getAttributeValue(attributeValues.get(0)));
                List <String> auxL = new ArrayList<String>();
                auxL.add(getAttributeValue(attributeValues.get(0)));
                attributeType.setValues(auxL.toArray(new String[0]));
            }
			
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
	
	public String[] getAttributeValuesFromCredentialNEW(XMLObject input) {
		
		if (input instanceof XSStringImpl) {
            return (new String[]{((XSStringImpl) input).getValue()});
        }

        if (input instanceof XSAnyImpl) {
            return (new String[]{((XSAnyImpl) input).getTextContent()});
        }
		
        return null;
	}
	
	
	public String[] getAttributeValuesFromCredential(List<XMLObject> input) {
		//String[] result;
		
		LOG.info("XMLObject: " + input.toString());
		
		ArrayList<String> ar = new ArrayList<String>();
		input.forEach((v)->{
			LOG.info("v: " + v);
			String value = getAttributeValue(v);
			LOG.info("value: " + value);
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
		LOG.info("StringAttributeValue: "+attributeValue.getValue());
	    return attributeValue.getValue();
	}

	private String getAnyAttributeValue(XSAnyImpl attributeValue)
	{
		LOG.info("AnyAttributeValue: "+attributeValue.getTextContent());
		return attributeValue.getTextContent();
		
	}
	
    
}
