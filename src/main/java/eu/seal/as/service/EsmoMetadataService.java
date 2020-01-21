/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service;

import java.io.IOException;
import java.security.KeyStoreException;

import eu.seal.as.model.pojo.EntityMetadata;

/**
 *
 * @author nikos
 */
public interface EsmoMetadataService {
    
    public EntityMetadata getMetadata() throws IOException, KeyStoreException;

}
