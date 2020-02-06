package eu.seal.idp.service.impl;

import io.jsonwebtoken.SignatureAlgorithm;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.seal.idp.service.KeyStoreService;
import eu.seal.idp.service.ParameterService;

/**
 *
 * @author nikos
 */
@Service
public class KeyStoreServiceImpl implements KeyStoreService {

    private final String certPath;
    private final String keyPass;
    private final String storePass;
    private final String jtwKeyAlias;
    private final String httpSigKeyAlias;

    private KeyStore keystore;

    @Autowired
    public KeyStoreServiceImpl() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        certPath = System.getenv("KEYSTORE_PATH");
        keyPass = System.getenv("KEY_PASS");
        storePass = System.getenv("STORE_PASS");
        jtwKeyAlias = System.getenv("JWT_CERT_ALIAS");
        httpSigKeyAlias = System.getenv("HTTPSIG_CERT_ALIAS");

        keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        if (!org.springframework.util.StringUtils.isEmpty(System.getenv("ASYNC_SIGNATURE")) && Boolean.parseBoolean(System.getenv("ASYNC_SIGNATURE"))) {
            File jwtCertFile = new File(certPath);
            InputStream certIS = new FileInputStream(jwtCertFile);
            keystore.load(certIS, storePass.toCharArray());
        } else {
            //init an empty keystore otherwise an exception is thrown
            keystore.load(null, null);
        }

    }

    public Key getSigningKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException {
        String asyncSignature = System.getenv("ASYNC_SIGNATURE");
        if (!org.springframework.util.StringUtils.isEmpty(asyncSignature) && Boolean.valueOf(asyncSignature)) {
            return keystore.getKey(httpSigKeyAlias, keyPass.toCharArray());
        }
        String secretKey = System.getenv("SIGNING_SECRET");
        System.out.print("This is the signing secret" + secretKey);
        return new SecretKeySpec(secretKey.getBytes("UTF-8"), 0, secretKey.length(), "HmacSHA256");
    }

    public Key getJWTPublicKey() throws KeyStoreException, UnsupportedEncodingException {
        //"jwtkey"
        String asyncSignature = System.getenv("ASYNC_SIGNATURE");
        if (!org.springframework.util.StringUtils.isEmpty(asyncSignature) && Boolean.valueOf(asyncSignature)) {
            Certificate cert = keystore.getCertificate(jtwKeyAlias);
            return cert.getPublicKey();
        }
        String secretKey = System.getenv("SIGNING_SECRET");
        return new SecretKeySpec(secretKey.getBytes("UTF-8"), 0, secretKey.length(), "HmacSHA256");
    }

    public Key getHttpSigPublicKey() throws KeyStoreException, UnsupportedEncodingException {
        //"httpSignaturesAlias"
        Certificate cert = keystore.getCertificate(httpSigKeyAlias);
        return cert.getPublicKey();

    }

    public KeyStore getKeystore() {
        return keystore;
    }

    public void setKeystore(KeyStore keystore) {
        this.keystore = keystore;
    }



    @Override
    public SignatureAlgorithm getAlgorithm() {
        if (!org.springframework.util.StringUtils.isEmpty(System.getenv("ASYNC_SIGNATURE")) && Boolean.parseBoolean(System.getenv("ASYNC_SIGNATURE"))) {
            return SignatureAlgorithm.RS256;
        }
        return SignatureAlgorithm.HS256;
    }

    @Override
    public String getFingerPrint() throws KeyStoreException, UnsupportedEncodingException {
        return DigestUtils.sha256Hex(this.getHttpSigPublicKey().getEncoded());
    }

}
