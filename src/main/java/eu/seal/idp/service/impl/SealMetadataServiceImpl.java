package eu.seal.idp.service.impl;

import eu.seal.idp.model.pojo.EndpointType;
import eu.seal.idp.model.pojo.EntityMetadata;
import eu.seal.idp.model.pojo.SecurityKeyType;
import eu.seal.idp.service.SealMetadataService;
import eu.seal.idp.service.KeyStoreService;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;


@Service
public class SealMetadataServiceImpl implements SealMetadataService {

    private final KeyStoreService keyServ;
    private final HashMap<String, String> displayNames;
    private final SecurityKeyType[] keyTypes;
    private final EndpointType[] endpoints;
    //String[] parts= new String[1];
    
    @Autowired
    public SealMetadataServiceImpl(KeyStoreService keyServ) throws KeyStoreException, UnsupportedEncodingException {
        this.keyServ = keyServ;

        displayNames = new HashMap();
        displayNames.put("en", "hello");

        keyTypes = new SecurityKeyType[2];
        

        EndpointType endpoint = new EndpointType("POST", "POST", "bye");
        endpoints = new EndpointType[]{endpoint};
    }

    @Override
    public EntityMetadata getMetadata() throws IOException, KeyStoreException {
        InputStream resource = new ClassPathResource(
                "static/logo.svg").getInputStream();
        byte[] fileContent = IOUtils.toByteArray(resource);//FileUtils.readFileToByteArray(inputFile);
        String encodedImage = Base64
                .getEncoder()
                .encodeToString(fileContent);
        
        //String[] claims = {"eduPersonAffiliation","primaryAffiliation","schacHomeOrganization","mail",
        //        "schacExpiryDate","mobile","eduPersonPrincipalName","eduPersonPrincipalNamePrior","displayName","sn","givenName"};
        String[] claims = {
                "schacHomeOrganization", "eduPersonTargetedID", "schGrAcPersonID",
                "uid", "schacGender", "schacYearOfBirth", "schacDateOfBirth",
                "schacCountryOfCitizenship", "schGrAcPersonSSN", "schacPersonalUniqueID",
                "eduPersonOrgDN", "mail", "eduPersonAffiliation", "eduPersonAffiliation",
                "eduPersonScopedAffiliation", "eduPersonPrimaryAffiliation", "givenName", "givenName_en",
                "givenName_el", "sn", "sn_el", "sn_en", "cn_en", "cn_el", "displayName", "schacPersonalPosition",
                "schacPersonalUniqueCode", "schGrAcEnrollment", "schGrAcInscription", "schGrAcPersonalLinkageID",
                "eduPersonEntitlement",
                "schGrAcPersonID", "ou", "dc", "schGrAcEnrollment",
                "eduPersonPrimaryAffiliation", "sn;lang-el",
                "mailLocalAddress", "sn;lang-en",
                "cn;lang-el", "eduPersonOrgDN", "schGrAcPersonID",
                "schacPersonalUniqueCode", "schacYearOfBirth",
                "schacPersonalPosition", "cn;lang-en",
                "schGrAcInscription", "eduPersonAffiliation",
                "schacCountryOfCitizenship", "schacPersonalUniqueID",
                "schacGender", "eduPersonScopedAffiliation",
                "schacHomeOrganization", "departmentNumber",
                "eduPersonEntitlement", "givenName;lang-en",
                "sn", "schGrAcPersonalLinkageID", "givenName;lang-el",
                "displayName", "mobile", "givenName", "cn"
        };
        String[] supportedSigningAlgs= new String[1];
        
        return new EntityMetadata("SEAL", "SEAL", this.displayNames, encodedImage,
                new String[]{""}, "OAUTH 2.0", new String[]{"RM"}, claims, //parts,
                this.endpoints, keyTypes, true, claims,
                true, supportedSigningAlgs, //parts, 
                null);
        
    }

}
