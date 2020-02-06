package eu.seal.idp.controllers;

import eu.seal.idp.service.EsmoMetadataService;
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
public class TokenGenerateController {

	private final static Logger LOG = LoggerFactory.getLogger(TokenGenerateController.class);

	private final NetworkService netServ;
	private final KeyStoreService keyServ;

	@Autowired
	public TokenGenerateController(KeyStoreService keyServ,
			EsmoMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
		this.keyServ = keyServ;
		Key signingKey = this.keyServ.getSigningKey();
		String fingerPrint = this.keyServ.getFingerPrint();
		HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
		this.netServ = new NetworkServiceImpl(httpSigServ);
	}
	
	/**
	 * Redirects an existing IDP request to the IDP 
	 */
	@RequestMapping(value = "generate/start", method = {RequestMethod.POST, RequestMethod.GET}, produces = "text/plain")
	@ResponseBody
	public String startSession() throws KeyStoreException, NoSuchAlgorithmException, IOException {
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		String rsp = netServ.sendPostForm(sessionMngrUrl, "/sm/startSession", requestParams, 1);
		return rsp;	
	}
	
	/**
	 * Redirects an existing IDP request to the IDP 
	 */	
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
	 * Store in sm from an existing token
	 */	
	@RequestMapping(value = "generate/storeSM", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/json")
	@ResponseBody
	public String storeSM(@RequestParam(value = "session", required = true) String sessionId, @RequestParam(value = "sender", required = true) String sender, @RequestParam(value = "receiver", required = true) String receiver,RedirectAttributes redirectAttrs) throws KeyStoreException, NoSuchAlgorithmException, IOException {
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		
		ObjectMapper mapper = new ObjectMapper();
		
		DataStore datastore = new DataStore();
		DataSet dataset = new DataSet();
		String idpRequestPlain = "{\"id\":\"_394a55a94873c15144a62678dafed1573503f4a6ab\",\"type\":\"Request\",\"issuer\":\"https:\\/\\/clave.sir2.rediris.es\\/module.php\\/saml\\/sp\\/saml2-acs.php\\/q2891006e_ea0002678\",\"recipient\":null,\"inResponseTo\":null,\"loa\":null,\"notBefore\":\"2019-12-17T11:50:54Z\",\"notAfter\":\"2020-12-15T11:55:54Z\",\"status\":{\"code\":null,\"subcode\":null,\"message\":null},\"attributes\":[{\"name\":\"https:\\/\\/software.internet2.edu\\/eduperson\\/internet2-mace-dir-eduperson-201602.html#eduPersonTargetedID \",\"friendlyName\":\"eduPersonTargetedID \",\"encoding\":\"UTF-8\",\"isMandatory\":false,\"values\":null},{\"name\":\"https:\\/\\/software.internet2.edu\\/eduperson\\/internet2-mace-dir-eduperson-201602.html#displayName\",\"friendlyName\":\"displayName\",\"encoding\":\"UTF-8\",\"isMandatory\":false,\"values\":null},{\"name\":\"https:\\/\\/software.internet2.edu\\/eduperson\\/internet2-mace-dir-eduperson-201602.html#cn\",\"friendlyName\":\"cn\",\"encoding\":\"UTF-8\",\"isMandatory\":false,\"values\":null},{\"name\":\"https:\\/\\/software.internet2.edu\\/eduperson\\/internet2-mace-dir-eduperson-201602.html#mail\",\"friendlyName\":\"mail\",\"encoding\":\"UTF-8\",\"isMandatory\":false,\"values\":null},{\"name\":\"https:\\/\\/software.internet2.edu\\/eduperson\\/internet2-mace-dir-eduperson-201602.html#eduPersonAffiliation\",\"friendlyName\":\"eduPersonAffiliation\",\"encoding\":\"UTF-8\",\"isMandatory\":false,\"values\":null},{\"name\":\"https:\\/\\/software.internet2.edu\\/eduperson\\/internet2-mace-dir-eduperson-201602.html#eduPersonScopedAffiliation\",\"friendlyName\":\"eduPersonScopedAffiliation\",\"encoding\":\"UTF-8\",\"isMandatory\":false,\"values\":null},{\"name\":\"https:\\/\\/www.terena.org\\/activities\\/tf-emc2\\/docs\\/schac\\/schac-20110705-1.4.1.schema.txt#schacHomeOrganization\",\"friendlyName\":\"schacHomeOrganization\",\"encoding\":\"UTF-8\",\"language\":null,\"isMandatory\":false,\"values\":null},{\"name\":\"https:\\/\\/www.terena.org\\/activities\\/tf-emc2\\/docs\\/schac\\/schac-20110705-1.4.1.schema.txt#schacHomeOrganizationType\",\"friendlyName\":\"schacHomeOrganizationType\",\"encoding\":\"UTF-8\",\"language\":null,\"isMandatory\":false,\"values\":null}],\"properties\":{\"SAML_RelayState\":\"\",\"SAML_RemoteSP_RequestId\":\"_d951f7da6fd1cb7d2de7ab4df483098e\",\"SAML_ForceAuthn\":true,\"SAML_isPassive\":false,\"SAML_NameIDFormat\":\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\",\"SAML_AllowCreate\":\"true\"}}";
		AttributeType[] result = new AttributeType[2];
		AttributeSetStatus atrSetStatus = new AttributeSetStatus();
		Map < String, String> metadataProperties = new HashMap();
		AttributeSet attrSet = new AttributeSet("id", TypeEnum.Response, "edugainASms_001", "CLms001", result, metadataProperties, sessionId, "low", null, null, atrSetStatus);
		String attributeSetString = mapper.writeValueAsString(datastore);
		
		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("sessionId", sessionId));
		requestParams.add(new NameValuePair("sender", sender));
		requestParams.add(new NameValuePair("receiver", receiver));
		
		
		
		UpdateDataRequest updateReq = new UpdateDataRequest(sessionId, "clientCallbackAddr", "http://https://github.com/EC-SEAL");
		UpdateDataRequest updateReqIdp = new UpdateDataRequest(sessionId, "idpRequest", idpRequestPlain);
		String rsp = netServ.sendPostBody(sessionMngrUrl, "/sm/updateSessionData", updateReq, "application/json", 1);
		return rsp;
	}
	
	/**
	 * 
	 */	
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
