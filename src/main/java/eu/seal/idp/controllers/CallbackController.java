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

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.idp.model.pojo.DataSet;
import eu.seal.idp.model.pojo.DataStore;
import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.model.pojo.UpdateDataRequest;
import eu.seal.idp.service.SealMetadataService;
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
			SealMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
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
	public String asCallback(@RequestParam(value = "session", required = true) String sessionId, Authentication authentication) throws NoSuchAlgorithmException, IOException {
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
		String callBackAddr = (String) smResp.getSessionData().getSessionVariables().get("clientCallbackAddr");


		// Recover DataStore
		String dataStoreString = (String) smResp.getSessionData().getSessionVariables().get("dataStore");
		List <DataSet> dsArrayList = new ArrayList();
		DataStore datastore = new DataStore();
		ObjectMapper mapper = new ObjectMapper();
		LOG.info("Recovered datastore \n" + datastore.toString());
		
		if(!StringUtils.isEmpty(dataStoreString)) {
			
			datastore = mapper.readValue(dataStoreString, DataStore.class);
			dsArrayList = datastore.getClearData();
		} else { 
			String datastoreId = UUID.randomUUID().toString();
			datastore.setId(datastoreId);
		}
		
		// Update DataStore with incoming DataSet
		DataSet receivedDataset = (new SAMLDatasetDetailsServiceImpl()).loadDatasetBySAML(recoveredSessionID, credentials);
		dsArrayList.add(receivedDataset);
		datastore.setClearData(dsArrayList);
		LOG.info("new Datastore \n" + datastore.toString());
		
		// Update Session Manager 
		String stringifiedDatastore = mapper.writeValueAsString(datastore);
		UpdateDataRequest updateReq = new UpdateDataRequest(sessionId, "dataStore", stringifiedDatastore);
		
		// Stores in the DataStore 
		String rsp = netServ.sendPostBody(sessionMngrUrl, "/sm/updateSessionData", updateReq, "application/json", 1);
		LOG.info("Response" + rsp);
		
		// Redirect to Callback Address
		return "redirect:" + callBackAddr; 
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
	public String isCallback(@RequestParam(value = "session", required = true) String sessionId, Authentication authentication) throws NoSuchAlgorithmException, IOException {
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
		String callBackAddr = (String) smResp.getSessionData().getSessionVariables().get("clientCallbackAddr");


//		// Recover DataStore
//		String dataStoreString = (String) smResp.getSessionData().getSessionVariables().get("dataStore");
//		List <DataSet> dsArrayList = new ArrayList();
//		DataStore datastore = new DataStore();
//		ObjectMapper mapper = new ObjectMapper();
//		LOG.info("Recovered datastore \n" + datastore.toString());
//		
//		if(!StringUtils.isEmpty(dataStoreString)) {
//			
//			datastore = mapper.readValue(dataStoreString, DataStore.class);
//			dsArrayList = datastore.getClearData();
//		} else { 
//			String datastoreId = UUID.randomUUID().toString();
//			datastore.setId(datastoreId);
//		}
//		
//		// Update DataStore with incoming DataSet
//		DataSet receivedDataset = (new SAMLDatasetDetailsServiceImpl()).loadDatasetBySAML(recoveredSessionID, credentials);
//		dsArrayList.add(receivedDataset);
//		datastore.setClearData(dsArrayList);
//		LOG.info("new Datastore \n" + datastore.toString());
//		
//		// Update Session Manager 
//		String stringifiedDatastore = mapper.writeValueAsString(datastore);
//		UpdateDataRequest updateReq = new UpdateDataRequest(sessionId, "dataStore", stringifiedDatastore);
//		
//		// Stores in the DataStore 
//		String rsp = netServ.sendPostBody(sessionMngrUrl, "/sm/updateSessionData", updateReq, "application/json", 1);
//		LOG.info("Response" + rsp);
		
		// Redirect to Callback Address
		return "redirect:" + callBackAddr; 
	}

}
