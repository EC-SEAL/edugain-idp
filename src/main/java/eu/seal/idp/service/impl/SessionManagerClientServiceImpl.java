package eu.seal.idp.service.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.commons.httpclient.NameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;


import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.service.HttpSignatureService;
import eu.seal.idp.service.KeyStoreService;
import eu.seal.idp.service.NetworkService;
import eu.seal.idp.service.SessionManagerClientService;

public class SessionManagerClientServiceImpl implements SessionManagerClientService {
	
	private final static Logger LOG = LoggerFactory.getLogger(SessionManagerClientServiceImpl.class);
	private final NetworkService netServ;
	private final KeyStoreService keyServ;
	private final String sessionMngrURL;
	ObjectMapper mapper = new ObjectMapper();
	
	public SessionManagerClientServiceImpl(KeyStoreService keyServ, String sessionMngrURL) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		this.keyServ = keyServ;
		this.sessionMngrURL = sessionMngrURL;
		Key signingKey = this.keyServ.getSigningKey();
		String fingerPrint = this.keyServ.getFingerPrint();
		HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
		this.netServ = new NetworkServiceImpl(httpSigServ);
	}
	
	public SessionMngrResponse validateToken(String param, String msToken) {
		SessionMngrResponse resp = new SessionMngrResponse();
		try {
			List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
			requestParams.add(new NameValuePair("token", msToken));
			ObjectMapper mapper = new ObjectMapper();
			String rspValidate = netServ.sendGet(sessionMngrURL, "/sm/validateToken", requestParams, 1);
			resp = mapper.readValue(rspValidate, SessionMngrResponse.class);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return resp;
	}
	
	
	public SessionMngrResponse getSingleParam(String key, String value) {
		try {
			String newUUID = UUID.randomUUID().toString();
			List<NameValuePair> requestParamsGet = new ArrayList<NameValuePair>();
			requestParamsGet.add(new NameValuePair(key, value));
			String clearRespGet = netServ.sendGet(sessionMngrURL, "/sm/getSessionData", requestParamsGet, 1);
			SessionMngrResponse respGet;
			respGet = mapper.readValue(clearRespGet, SessionMngrResponse.class);
			return respGet;
		} catch (Exception e) {
			e.printStackTrace();
			return new SessionMngrResponse();
		}
	}
}
