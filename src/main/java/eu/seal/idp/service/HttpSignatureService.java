package eu.seal.idp.service;



import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

import eu.seal.idp.enums.HttpResponseEnum;

/**
 *
 * @author nikos
 */
public interface HttpSignatureService {

    public String generateSignature(String hostUrl, String method, String uri, Object postParams, String contentType, String requestId)
            throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, UnsupportedEncodingException, IOException, UnsupportedEncodingException;
    
    public HttpResponseEnum verifySignature(HttpServletRequest httpRequest, Optional<PublicKey> publicKeyToCheckWith) ;
    
    
    

}
