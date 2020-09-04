package eu.seal.idp.controllers;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.idp.model.pojo.AttributeSet;
import eu.seal.idp.model.pojo.DataSet;
import eu.seal.idp.model.pojo.DataStore;
import eu.seal.idp.model.pojo.DataStoreObject;
import eu.seal.idp.model.pojo.DataStoreObjectList;
import eu.seal.idp.model.pojo.EntityMetadata;
import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.service.SealMetadataService;
import eu.seal.idp.service.HttpSignatureService;
import eu.seal.idp.service.KeyStoreService;
import eu.seal.idp.service.NetworkService;
import eu.seal.idp.service.impl.DataStoreServiceImpl;
import eu.seal.idp.service.impl.HttpSignatureServiceImpl;
import eu.seal.idp.service.impl.NetworkServiceImpl;
import eu.seal.idp.service.impl.SAMLDatasetDetailsServiceImpl;
import eu.seal.idp.service.impl.SessionManagerClientServiceImpl;

@Controller
public class CallbackController {

	private final NetworkService netServ;
	private final KeyStoreService keyServ;
	private final SealMetadataService metadataServ;
	private final SessionManagerClientServiceImpl sessionManagerClient;
	private final String sessionManagerURL;
	private final String responseSenderID;

	private String rmResponseReceiverID;
	private String clResponseReceiverID;

	ObjectMapper mapper;
	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(CallbackController.class);

	@Autowired
	public CallbackController(KeyStoreService keyServ, SealMetadataService metadataServ)
			throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException,
			InvalidKeySpecException, IOException {
		this.keyServ = keyServ;
		this.metadataServ = metadataServ;
		this.sessionManagerURL = System.getenv("SESSION_MANAGER_URL");
		this.responseSenderID = System.getenv("RESPONSE_SENDER_ID");
		this.rmResponseReceiverID = System.getenv("RM_RESPONSE_RECEIVER_ID");
		this.clResponseReceiverID = System.getenv("CL_RESPONSE_RECEIVER_ID");
		this.sessionManagerClient = new SessionManagerClientServiceImpl(keyServ, sessionManagerURL);
		this.mapper = new ObjectMapper();
		HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(this.keyServ.getFingerPrint(),
				this.keyServ.getSigningKey());
		this.netServ = new NetworkServiceImpl(httpSigServ);
	}

	/**
	 * Manages SAML success callback (mapped from /saml/SSO callback) and writes to
	 * the DataStore
	 * 
	 * @param session
	 * @param authentication
	 * @param model
	 * @param redirectAttrs
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */

	@RequestMapping("/callback")
	@ResponseBody
	public ModelAndView isCallback(@RequestParam(value = "session", required = true) String sessionId,
			Authentication authentication, Model model) throws NoSuchAlgorithmException, IOException {
		SessionMngrResponse smResp = sessionManagerClient.getSingleParam("sessionId", sessionId);
		LOG.info(smResp.toString());
		String callBackAddr = (String) smResp.getSessionData().getSessionVariables().get("ClientCallbackAddr");
		if (callBackAddr == null) {
			callBackAddr = "#";
			return dataStoreHandler(sessionId, authentication, callBackAddr, model);
		} else if (callBackAddr.contains("rm/response")) {
			return dsResponseHandler(sessionId, authentication, callBackAddr, model);
		} else {
			return dataStoreHandler(sessionId, authentication, callBackAddr, model);
		}
	}

	public ModelAndView dsResponseHandler(String sessionId, Authentication authentication, String callBackAddr,
			Model model) {
		//TO BE TESTED
		
		authentication.getDetails();
		try {
			SAMLCredential credentials = (SAMLCredential) authentication.getCredentials();
			AttributeSet receivedAttributeSet = (new SAMLDatasetDetailsServiceImpl())
					.loadAttributeSetBySAML(UUID.randomUUID().toString(), sessionId, credentials);
			//String stringifiedAsResponse = mapper.writeValueAsString(receivedAttributeSet);

			EntityMetadata metadata = this.metadataServ.getMetadata();
			//String stringifiedMetadata = mapper.writeValueAsString(metadata);
			//LOG.info(stringifiedMetadata);
			
			//sessionManagerClient.updateSessionVariables(sessionId, sessionId,"dsResponse", stringifiedAsResponse);
			//sessionManagerClient.updateSessionVariables(sessionId, sessionId,"dsMetadata", stringifiedMetadata);
			
			sessionManagerClient.updateSessionVariables(sessionId, sessionId,"dsResponse", receivedAttributeSet);
			sessionManagerClient.updateSessionVariables(sessionId, sessionId,"dsMetadata", metadata);
			

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		SessionMngrResponse tokenCreate = sessionManagerClient.generateToken(sessionId, responseSenderID,
				rmResponseReceiverID);

		model.addAttribute("callback", callBackAddr);
		model.addAttribute("msToken", tokenCreate.getAdditionalData());
		return new ModelAndView("clientRedirect");
	}
	
	
	public ModelAndView dataStoreHandler(String sessionId, Authentication authentication, String callBackAddr,
			Model model) {
		try {
			authentication.getDetails();
			SAMLCredential credentials = (SAMLCredential) authentication.getCredentials();
			//SessionMngrResponse smResp = sessionManagerClient.getSingleParam("sessionId", sessionId);  // what for?
			
			DataSet rtrDataSet = (new SAMLDatasetDetailsServiceImpl())
					.loadDatasetBySAML(UUID.randomUUID().toString(), credentials);
			LOG.info("DataSet: " + rtrDataSet.toString());
			
			
			String inResponseTo = sessionId;
			AttributeSet authSet = (new SAMLDatasetDetailsServiceImpl())
					.loadAttributeSetBySAML(UUID.randomUUID().toString(), inResponseTo, credentials);
			LOG.info("***TO ASK INRESPONSETO -->AuthenticationSet: " + authSet.toString());
			// the ID of the request which the set is responding to
			// From the SPrequest?
			
			String objectId =(new SAMLDatasetDetailsServiceImpl())
					.getUniqueIdFromCredentials(credentials);  // Calculate eduPersonTargetedIdentifier SHA1
			
			sessionManagerClient.updateDatastore(sessionId, objectId, rtrDataSet);					
			sessionManagerClient.updateSessionVariables(sessionId, sessionId,"authenticationSet", authSet);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		SessionMngrResponse tokenCreate = sessionManagerClient.generateToken(sessionId, responseSenderID,
				clResponseReceiverID);

		model.addAttribute("callback", callBackAddr);
		model.addAttribute("msToken", tokenCreate.getAdditionalData());
		return new ModelAndView("clientRedirect");

	}


}
