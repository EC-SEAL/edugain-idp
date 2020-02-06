package eu.seal.idp.controllers;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.httpclient.NameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.idp.model.pojo.DataSet;
import eu.seal.idp.model.pojo.DataStore;
import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.service.EsmoMetadataService;
import eu.seal.idp.service.HttpSignatureService;
import eu.seal.idp.service.KeyStoreService;
import eu.seal.idp.service.NetworkService;
import eu.seal.idp.service.impl.HttpSignatureServiceImpl;
import eu.seal.idp.service.impl.NetworkServiceImpl;
import eu.seal.idp.service.impl.SAMLDatasetDetailsServiceImpl;

@Controller
public class CallbackController {
	
	private final NetworkService netServ;
	private final KeyStoreService keyServ;
	// Logger
	private static final Logger LOG = LoggerFactory
			.getLogger(CallbackController.class);
	
	@Autowired
	public CallbackController(KeyStoreService keyServ,
			EsmoMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
		this.keyServ = keyServ;
		Key signingKey = this.keyServ.getSigningKey();
		String fingerPrint = this.keyServ.getFingerPrint();
		HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
		this.netServ = new NetworkServiceImpl(httpSigServ);
	}
	
	/**
	 * Manages SAML success callback (mapped from /saml/SSO callback) and writes to the DataStore
	 * @param session 
	 * @param authentication
	 * @param model
	 * @param redirectAttrs
	 * @return 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	
	@RequestMapping("/as/callback")
	@ResponseBody
	public String callback(@RequestParam(value = "session", required = true) String sessionId, Authentication authentication) throws NoSuchAlgorithmException, IOException {
		authentication.getDetails();
		SAMLCredential credentials = (SAMLCredential) authentication.getCredentials();		
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		
		// Request Session Data
		List<NameValuePair> requestParams = new ArrayList<>();
		requestParams.add(new NameValuePair("sessionId", sessionId));
		String clearSmResp = netServ.sendGet(sessionMngrUrl, "/sm/getSessionData",requestParams, 1);
		
		// Recover Session ID
		SessionMngrResponse smResp = (new ObjectMapper()).readValue(clearSmResp, SessionMngrResponse.class);
		String recoveredSessionID = smResp.getSessionData().getSessionId(); 
		// Generate Datastore
		DataStore datastore = new DataStore();
		DataSet dataset = (new SAMLDatasetDetailsServiceImpl()).loadDatasetBySAML(recoveredSessionID, credentials);;
		
		// Get Callback Address
		String callBackAddr = (String) smResp.getSessionData().getSessionVariables().get("clientCallbackAddr");
		return "redirect:/" + callBackAddr; // Change with the callback 
	}

}
