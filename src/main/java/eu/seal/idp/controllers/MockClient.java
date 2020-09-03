package eu.seal.idp.controllers;

import eu.seal.idp.service.SealMetadataService;
import eu.seal.idp.service.HttpSignatureService;
import eu.seal.idp.service.KeyStoreService;
import eu.seal.idp.service.NetworkService;
import eu.seal.idp.service.impl.HttpSignatureServiceImpl;
import eu.seal.idp.service.impl.NetworkServiceImpl;
import eu.seal.idp.enums.TypeEnum;
import eu.seal.idp.model.pojo.AttributeSet;
import eu.seal.idp.model.pojo.AttributeSetStatus;
import eu.seal.idp.model.pojo.AttributeType;
import eu.seal.idp.model.pojo.DataSet;
import eu.seal.idp.model.pojo.DataStore;
import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.model.pojo.UpdateDataRequest;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.NameValuePair;
import org.slf4j.Logger;	
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Controllers managing Seal Authentication Source, used in the log in and SSO Callback
 */
@Controller
public class MockClient {

	private final static Logger LOG = LoggerFactory.getLogger(MockClient.class);

	private final NetworkService netServ;
	private final KeyStoreService keyServ;

	@Autowired
	public MockClient(KeyStoreService keyServ,
			SealMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
		this.keyServ = keyServ;
		Key signingKey = this.keyServ.getSigningKey();
		String fingerPrint = this.keyServ.getFingerPrint();
		HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
		this.netServ = new NetworkServiceImpl(httpSigServ);
	}
	
	@RequestMapping(value = "generate/generateToken", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/json")
	@ResponseBody
	public String generateToken(@RequestParam(value = "session", required = true) String sessionID, @RequestParam(value = "sender", required = true) String sender, @RequestParam(value = "receiver", required = true) String receiver,RedirectAttributes redirectAttrs) throws KeyStoreException, NoSuchAlgorithmException, IOException {
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("sessionId", sessionID));
		requestParams.add(new NameValuePair("sender", sender));
		requestParams.add(new NameValuePair("receiver", receiver));
		String rsp = netServ.sendGet(sessionMngrUrl, "/sm/generateToken", requestParams, 1);
		return rsp;	
	}
	
	/**
	 * Gets data from SM
	 */	
	@RequestMapping(value = "generate/getSessionData", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/json")
	@ResponseBody
	public String getSM(@RequestParam(value = "session", required = true) String sessionId, @RequestParam(value = "sender", required = true) String sender, @RequestParam(value = "receiver", required = true) String receiver,RedirectAttributes redirectAttrs) throws KeyStoreException, NoSuchAlgorithmException, IOException {
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("sessionId", sessionId));
		
		String rsp = netServ.sendGet(sessionMngrUrl, "/sm/getSessionData",requestParams, 1);
		return rsp;
	}
	
	/**
	 * Gets data from SM/new
	 */	
	@RequestMapping(value = "generate/getDataStore", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/json")
	@ResponseBody
	public String getSMnew(@RequestParam(value = "session", required = true) String sessionId, @RequestParam(value = "sender", required = true) String sender, @RequestParam(value = "receiver", required = true) String receiver,RedirectAttributes redirectAttrs) throws KeyStoreException, NoSuchAlgorithmException, IOException {
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("sessionId", sessionId));
		
		//String rsp = netServ.sendGet(sessionMngrUrl, "/sm/new/get",requestParams, 1);
		SessionMngrResponse rsp = netServ.sendGetSMResponse(sessionMngrUrl, "/sm/new/get",requestParams, 1);
		
		return rsp.getAdditionalData();
	}
		
	
	@RequestMapping(value = "generate/validateToken", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/json")
	@ResponseBody
	public String validateToken(@RequestParam(value = "msToken", required = true) String msToken, @RequestParam(value = "sender", required = true) String sender, @RequestParam(value = "receiver", required = true) String receiver,RedirectAttributes redirectAttrs) throws KeyStoreException, NoSuchAlgorithmException, IOException {
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("token", msToken));
		ObjectMapper mapper = new ObjectMapper();
		String resp = netServ.sendGet(sessionMngrUrl, "/sm/validateToken", requestParams, 1);
		return resp;
	}
}
