/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service.impl;

import eu.seal.as.model.pojo.EndpointType;
import eu.seal.as.model.pojo.EntityMetadata;
import eu.seal.as.model.pojo.EsmoSecurityUsage;
import eu.seal.as.model.pojo.SecurityKeyType;
import eu.seal.as.service.EsmoMetadataService;
import eu.seal.as.service.KeyStoreService;
import eu.seal.as.service.ParameterService;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

/**
 *
 * @author nikos
 */
@Service
public class EsmoMetadataServiceImpl implements EsmoMetadataService {

    private final KeyStoreService keyServ;
    private final HashMap<String, String> displayNames;
    private final SecurityKeyType[] keyTypes;
    private final EndpointType[] endpoints;

    private final ParameterService paramServ;

    @Autowired
    public EsmoMetadataServiceImpl(KeyStoreService keyServ, ParameterService paramServ) throws KeyStoreException, UnsupportedEncodingException {
        this.keyServ = keyServ;
        this.paramServ = paramServ;

        displayNames = new HashMap();
        displayNames.put("en", paramServ.getParam("ESMO_SERVICE_DESCRIPTION"));

        keyTypes = new SecurityKeyType[2];
////        String httpSigKey = new String(keyServ.getHttpSigPublicKey().getEncoded(), StandardCharsets.UTF_8);
////        SecurityKeyType httpSigKeyType = new SecurityKeyType("RSAPublicKey", EsmoSecurityUsage.signing, httpSigKey);
////        keyTypes[0] = httpSigKeyType;
////        if (this.keyServ.getJWTPublicKey() != null) {
////            String jwtKey = new String(this.keyServ.getJWTPublicKey().getEncoded(), StandardCharsets.UTF_8);
////            SecurityKeyType jwtKeyType = new SecurityKeyType("RSAPublicKey", EsmoSecurityUsage.signing, jwtKey);
////            keyTypes[1] = jwtKeyType;
////        }
        EndpointType endpoint = new EndpointType("POST", "POST", paramServ.getParam("ESMO_EXPOSE_URL"));
        endpoints = new EndpointType[]{endpoint};
    }

    @Override
    public EntityMetadata getMetadata() throws IOException, KeyStoreException {
        InputStream resource = new ClassPathResource(
                "static/img/uaegeanI4m.png").getInputStream();
        byte[] fileContent = IOUtils.toByteArray(resource);//FileUtils.readFileToByteArray(inputFile);
        String encodedImage = Base64
                .getEncoder()
                .encodeToString(fileContent);
        
        String[] claims = (String[]) Arrays.asList("eduPersonAffiliation","primaryAffiliation","schacHomeOrganization","mail",
                "schacExpiryDate","mobile","eduPersonPrincipalName","eduPersonPrincipalNamePrior","displayName","sn","givenName").toArray();
        
        return new EntityMetadata("https://aegean.gr/esmo/gw/ap/metadata", paramServ.getParam("ESMO_DEFAULT_NAME"), this.displayNames, encodedImage,
                new String[]{"Greece"}, "OAUTH 2.0", new String[]{"ACM"}, paramServ.getParam("SUPPORTED_CLAIMS").split(","),
                this.endpoints, keyTypes, true, claims,
                true, paramServ.getParam("ESMO_SUPPORTED_ENC_ALGORITHMS").split(","), null);
    }

}
