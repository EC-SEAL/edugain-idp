/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service;



import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import eu.seal.as.model.pojo.MSConfigurationResponse.MicroService;

/**
 *
 * @author nikos
 */
public interface MSConfigurationService {

    public MicroService[] getConfigurationJSON();

    public Optional<String> getMsIDfromRSAFingerprint(String rsaFingerPrint) throws IOException;

    public Optional<PublicKey> getPublicKeyFromFingerPrint(String rsaFingerPrint) throws InvalidKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException;

    public String getMsEndpointByIdAndApiCall(String msId, String apiCall);

}
