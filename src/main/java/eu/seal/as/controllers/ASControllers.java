/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import eu.seal.as.MemCacheConfig;
import eu.seal.as.enums.TypeEnum;
import eu.seal.as.model.factories.AttributeTypeFactory;
import eu.seal.as.model.pojo.AttributeSet;
import eu.seal.as.model.pojo.AttributeSetStatus;
import eu.seal.as.model.pojo.AttributeType;
import eu.seal.as.model.pojo.EntityMetadata;
	import eu.seal.as.model.pojo.SessionMngrResponse;
import eu.seal.as.model.pojo.UpdateDataRequest;
import eu.seal.as.service.EsmoMetadataService;
import eu.seal.as.service.HttpSignatureService;
import eu.seal.as.service.KeyStoreService;
import eu.seal.as.service.NetworkService;
import eu.seal.as.service.ParameterService;
import eu.seal.as.service.impl.HttpSignatureServiceImpl;
import eu.seal.as.service.impl.NetworkServiceImpl;
import eu.seal.as.service.impl.SamlUtils;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Controllers managing Seal Authentication Source, used in the log in and SSO Callback
 */
@Controller
public class ASControllers {

	private final static Logger LOG = LoggerFactory.getLogger(ASControllers.class);

	private final NetworkService netServ;
	private final EsmoMetadataService metadataServ;
	private final KeyStoreService keyServ;

	@Autowired
	public ASControllers(ParameterService paramServ, KeyStoreService keyServ,
			EsmoMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
		this.metadataServ = metadataServ;
		this.keyServ = keyServ;
		Key signingKey = this.keyServ.getSigningKey();
		String fingerPrint = this.keyServ.getFingerPrint();
		HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
		this.netServ = new NetworkServiceImpl(httpSigServ);
	}
	
	/**
	 * Redirects an existing IDP request to the IDP 
	 * @param msToken
	 * @param model
	 * @param redirectAttrs
	 * @return
	 * @throws KeyStoreException
	 */

	@RequestMapping(value = "/as/authenticate", method = {RequestMethod.POST, RequestMethod.GET})
	public String authenticate(@RequestParam(value = "msToken", required = false) String msToken, Model model, RedirectAttributes redirectAttrs) throws KeyStoreException {
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");

		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("token", msToken));
		ObjectMapper mapper = new ObjectMapper();    

		try {
			SessionMngrResponse resp = mapper.readValue(netServ.sendGet(sessionMngrUrl, "/sm/validateToken", requestParams, 1), SessionMngrResponse.class);
			if (resp.getCode().toString().equals("OK") && StringUtils.isEmpty(resp.getError())) {
				String sealSessionId = resp.getSessionData().getSessionId();
				requestParams.clear();
				requestParams.add(new NameValuePair("sessionId", sealSessionId));
				Gson gson = new Gson();
				LinkedHashMap<?, ?> apRequest = (LinkedHashMap<?, ?>) resp.getSessionData().getSessionVariables().get("apRequest");
				String jsonApRequest = gson.toJson(apRequest, LinkedHashMap.class);

				LOG.info("* Session:" + apRequest + "\n" + "* Correct data:" + jsonApRequest);

				if (apRequest == null) {
					LOG.error("no apRequest found in session" + sealSessionId);
					model.addAttribute("error", "No AP request attributes found in the Session! Please restart the process");
					redirectAttrs.addFlashAttribute("errorMsg", "No AP request attributes found in the Session! Please restart the process");
					return "redirect:/authfail";
				} else {
					return "redirect:/grap/saml/login?session=" + sealSessionId;
				}
			} else {
				model.addAttribute("error", "Error validating token! " + resp.getError());
				LOG.error("something wring with the SM session!" + resp.getError());
				redirectAttrs.addFlashAttribute("errorMsg", "Error validating token! " + resp.getError());
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return "redirect:/authfail";
		} catch (IOException e) {
			e.printStackTrace();
		} 
		return "redirect:/saml/login";
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

	@RequestMapping(value = "/as/samlSuccess", method = {RequestMethod.POST})
	public String samlSuccessResponseSession(@RequestParam(value = "session", required = false) String session,
			Authentication authentication, Model model, RedirectAttributes redirectAttrs) throws IOException, NoSuchAlgorithmException, KeyStoreException {
		authentication.getDetails();
		SAMLCredential credentials = (SAMLCredential) authentication.getCredentials();
		List<String> attributes = Arrays.asList(
				"schacHomeOrganization", "eduPersonTargetedID", "schGrAcPersonID",
				"uid", "schacGender", "schacYearOfBirth", "schacDateOfBirth",
				"schacCountryOfCitizenship", "schGrAcPersonSSN", "schacPersonalUniqueID",
				"eduPersonScopedAffiliation", "eduPersonPrimaryAffiliation", "givenName", "givenName_en",
				"givenName_el", "sn", "sn_el", "sn_en", "cn_en", "cn_el", "displayName", "schacPersonalPosition",
				"schacPersonalUniqueCode", "schGrAcEnrollment", "schGrAcInscription", "schGrAcPersonalLinkageID",
				"eduPersonEntitlement",
				"schGrAcPersonID", "ou", "dc", "schGrAcEnrollment",
				"eduPersonPrimaryAffiliation", "sn;lang-el",
				"mailLocalAddress", "sn;lang-en",
				"cn;lang-el", "eduPersonOrgDN", "schGrAcPersonID",
				"schacPersonalUniqueCode", "schacYearOfBirth",
				"schacPersonalPosition", "cn;lang-en",
				"schGrAcInscription", "eduPersonAffiliation",
				"schacCountryOfCitizenship", "schacPersonalUniqueID",
				"schacGender", "eduPersonScopedAffiliation",
				"schacHomeOrganization", "departmentNumber",
				"eduPersonEntitlement", "givenName;lang-en",
				"sn", "schGrAcPersonalLinkageID", "givenName;lang-el",
				"displayName", "mobile", "givenName", "cn"
		);

		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		List<NameValuePair> requestParams = new ArrayList<>();
		ObjectMapper mapper = new ObjectMapper();
		SessionMngrResponse resp = mapper.readValue(session, SessionMngrResponse.class);
		String sealSessionId = resp.getSessionData().getSessionId();

		List<Attribute> returnedAttributes
		= attributes.stream()
		.map(attrName -> {
			return SamlUtils.getByFriendlyName(credentials.getAttributes(), attrName);
		})
		.filter(attr -> {
			return attr.isPresent();
		})
		.map(attr -> {
			LOG.info(attr.toString());
			return attr.get();
		}).collect(Collectors.toList());
		
		AttributeType[] result = AttributeTypeFactory.makeFromSamlAttribute(returnedAttributes);
		
		LOG.info(result.toString());
		
		// Create Dataset
		
		
		
		
		// Create Datastore
		
		return "redirect:/authfail";
	}

}

