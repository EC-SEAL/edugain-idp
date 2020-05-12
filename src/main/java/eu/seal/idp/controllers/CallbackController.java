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
import java.util.UUID;

import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.lang3.StringUtils;
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
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.idp.model.pojo.DataSet;
import eu.seal.idp.model.pojo.DataStore;
import eu.seal.idp.model.pojo.EntityMetadata;
import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.model.pojo.UpdateDataRequest;
import eu.seal.idp.service.SealMetadataService;
import eu.seal.idp.service.HttpSignatureService;
import eu.seal.idp.service.KeyStoreService;
import eu.seal.idp.service.NetworkService;
import eu.seal.idp.service.impl.DataStoreServiceImpl;
import eu.seal.idp.service.impl.HttpSignatureServiceImpl;
import eu.seal.idp.service.impl.NetworkServiceImpl;
import eu.seal.idp.service.impl.SAMLDatasetDetailsServiceImpl;
import eu.seal.idp.service.impl.SessionManagerClientImpl;

@Controller
public class CallbackController {
	
	private final NetworkService netServ;
	private final KeyStoreService keyServ;
	private final SealMetadataService metadataServ;
	private final SessionManagerClientImpl sessionManagerClient;
	private final String sessionManagerURL;
	// Logger
	private static final Logger LOG = LoggerFactory
			.getLogger(CallbackController.class);
	
	@Autowired
	public CallbackController(KeyStoreService keyServ,
			SealMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
		this.keyServ = keyServ;
		this.metadataServ=metadataServ;
		this.sessionManagerURL = System.getenv("SESSION_MANAGER_URL");
		this.sessionManagerClient = new SessionManagerClientImpl(keyServ, sessionManagerURL);
		HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(this.keyServ.getFingerPrint(), this.keyServ.getSigningKey());
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
	
	@RequestMapping("/is/callback")
	@ResponseBody
	public ModelAndView isCallback(@RequestParam(value = "session", required = true) String sessionId, Authentication authentication) throws NoSuchAlgorithmException, IOException {
		authentication.getDetails();
		SAMLCredential credentials = (SAMLCredential) authentication.getCredentials();	
		SessionMngrResponse smResp = sessionManagerClient.getSingleParam("sessionId", sessionId);
		String callBackAddr = (String) smResp.getSessionData().getSessionVariables().get("clientCallbackAddr");

		// Recover DataStore
		String dataStoreString = (String) smResp.getSessionData().getSessionVariables().get("dataStore");
		DataStore rtrDatastore = new DataStore();
		ObjectMapper mapper = new ObjectMapper();
		rtrDatastore = mapper.readValue(dataStoreString, DataStore.class);
		DataSet rtrDataSet = (new SAMLDatasetDetailsServiceImpl()).loadDatasetBySAML(sessionId, credentials);
		
		rtrDatastore=(new DataStoreServiceImpl()).pushDataSet(rtrDatastore,rtrDataSet);
		String stringifiedDatastore = mapper.writeValueAsString(rtrDatastore);
		UpdateDataRequest updateReq = new UpdateDataRequest(sessionId, "dataStore", stringifiedDatastore);
				
		netServ.sendPostBody(sessionManagerURL, "/sm/updateSessionData", updateReq, "application/json", 1);
		
		// Redirect to Callback Address
		return new ModelAndView("redirect:" + callBackAddr); 		
	}
	
	/**
	 * Manages SAML IS success callback (mapped from /saml/SSO callback) and writes to the DataStore
	 * @param session 
	 * @param authentication
	 * @param model
	 * @param redirectAttrs
	 * @return 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	
	@RequestMapping("/as/callback")
	@ResponseBody
	public ModelAndView asCallback(@RequestParam(value = "session", required = true) String sessionId, Authentication authentication) throws NoSuchAlgorithmException, IOException, KeyStoreException {
		authentication.getDetails();
		SAMLCredential credentials = (SAMLCredential) authentication.getCredentials();		
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		
		// Request Session Data
		List<NameValuePair> requestParams = new ArrayList<>();
		requestParams.add(new NameValuePair("sessionId", sessionId));
		String clearSmResp = netServ.sendGet(sessionMngrUrl, "/sm/getSessionData",requestParams, 1);
		ObjectMapper mapper = new ObjectMapper();
		
		// Recover Session ID
		SessionMngrResponse smResp = (new ObjectMapper()).readValue(clearSmResp, SessionMngrResponse.class);
		
		//Recover Dataset and Metadata
		DataSet receivedDataset = (new SAMLDatasetDetailsServiceImpl()).loadDatasetBySAML(sessionId, credentials);
		String stringifiedDsResponse = mapper.writeValueAsString(receivedDataset);

		//UpdateSessionmanager with DSResponse and DSMetadata
		UpdateDataRequest updateReqResponse = new UpdateDataRequest(sessionId, "dsResponse", stringifiedDsResponse);
		UpdateDataRequest updateReqMetadata = new UpdateDataRequest(sessionId, "dsMetadata", stringifiedDsResponse);

		netServ.sendPostBody(sessionMngrUrl, "/sm/updateSessionData", updateReqResponse, "application/json", 1);
		netServ.sendPostBody(sessionMngrUrl, "/sm/updateSessionData", updateReqMetadata, "application/json", 1);
		
		// Redirect to Callback Address
		String callBackAddr = (String) smResp.getSessionData().getSessionVariables().get("clientCallbackAddr");
		return new ModelAndView("redirect:" + callBackAddr); 
	}

}
