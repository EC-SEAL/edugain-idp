package eu.seal.idp.service.impl;

import eu.seal.idp.model.pojo.EndpointType;
import eu.seal.idp.model.pojo.EntityMetadata;
import eu.seal.idp.model.pojo.SecurityKeyType;
import eu.seal.idp.service.EsmoMetadataService;
import eu.seal.idp.service.KeyStoreService;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStoreException;
import java.util.Base64;
import java.util.HashMap;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;


@Service
public class EsmoMetadataServiceImpl implements EsmoMetadataService {

    private final KeyStoreService keyServ;
    private final HashMap<String, String> displayNames;
    private final SecurityKeyType[] keyTypes;
    private final EndpointType[] endpoints;

    @Autowired
    public EsmoMetadataServiceImpl(KeyStoreService keyServ) throws KeyStoreException, UnsupportedEncodingException {
        this.keyServ = keyServ;

        displayNames = new HashMap();
        displayNames.put("en", System.getenv("SEAL_SERVICE_DESCRIPTION"));

        keyTypes = new SecurityKeyType[2];

        EndpointType endpoint = new EndpointType("POST", "POST", System.getenv("ESMO_EXPOSE_URL"));
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
        
        String[] claims = {"eduPersonAffiliation","primaryAffiliation","schacHomeOrganization","mail",
                "schacExpiryDate","mobile","eduPersonPrincipalName","eduPersonPrincipalNamePrior","displayName","sn","givenName"};
        
        return new EntityMetadata("https://aegean.gr/esmo/gw/ap/metadata", System.getenv("ESMO_DEFAULT_NAME"), this.displayNames, encodedImage,
                new String[]{"Greece"}, "OAUTH 2.0", new String[]{"ACM"}, System.getenv("SUPPORTED_CLAIMS").split(","),
                this.endpoints, keyTypes, true, claims,
                true, System.getenv("ESMO_SUPPORTED_ENC_ALGORITHMS").split(","), null);
    }

}
