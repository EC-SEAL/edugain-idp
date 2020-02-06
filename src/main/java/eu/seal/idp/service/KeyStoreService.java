package eu.seal.idp.service;

import io.jsonwebtoken.SignatureAlgorithm;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;


public interface KeyStoreService {

    public Key getSigningKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException,UnsupportedEncodingException;
    public Key getJWTPublicKey() throws KeyStoreException, UnsupportedEncodingException;
    public Key getHttpSigPublicKey() throws KeyStoreException, UnsupportedEncodingException;
    public SignatureAlgorithm getAlgorithm();
    public String getFingerPrint() throws KeyStoreException, UnsupportedEncodingException;;
}
