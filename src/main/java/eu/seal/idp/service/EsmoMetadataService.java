package eu.seal.idp.service;

import java.io.IOException;
import java.security.KeyStoreException;

import eu.seal.idp.model.pojo.EntityMetadata;


public interface EsmoMetadataService {
    
    public EntityMetadata getMetadata() throws IOException, KeyStoreException;

}
