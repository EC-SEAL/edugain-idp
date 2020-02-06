
package eu.seal.idp.controllers;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.service.EsmoMetadataService;
import eu.seal.idp.service.HttpSignatureService;
import eu.seal.idp.service.KeyStoreService;
import eu.seal.idp.service.NetworkService;
import eu.seal.idp.service.impl.HttpSignatureServiceImpl;
import eu.seal.idp.service.impl.NetworkServiceImpl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;	
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Controllers managing Seal Authentication Source, used in the log in and SSO Callback
 *  */

@Controller
public class AuthenticateController {

	private final static Logger LOG = LoggerFactory.getLogger(AuthenticateController.class);

	private final NetworkService netServ;
	private final KeyStoreService keyServ;

	@Autowired
	public AuthenticateController(KeyStoreService keyServ,
			EsmoMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
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
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws JsonMappingException 
	 * @throws JsonParseException 
	 */

	@RequestMapping(value = "/as/authenticate", method = {RequestMethod.POST, RequestMethod.GET})
	public String authenticate(@RequestParam(value = "msToken", required = true) String msToken, RedirectAttributes redirectAttrs) throws KeyStoreException, JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException {
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");

		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("token", msToken));
		ObjectMapper mapper = new ObjectMapper();
		String rspValidate = netServ.sendGet(sessionMngrUrl, "/sm/validateToken", requestParams, 1);
		SessionMngrResponse resp = mapper.readValue(rspValidate, SessionMngrResponse.class);

		if (resp.getCode().toString().equals("OK") && StringUtils.isEmpty(resp.getError())) {
			String sealSessionId = resp.getSessionData().getSessionId();
			requestParams.clear();
			requestParams.add(new NameValuePair("sessionId", sealSessionId));
			System.out.print("Session ID" + sealSessionId);
			
			LinkedHashMap<?, ?> idpRequest = (LinkedHashMap<?, ?>) resp.getSessionData().getSessionVariables().get("idpRequest");
			if (idpRequest == null) {
				LOG.error("no idpRequest found in session" + sealSessionId);
				return "redirect:/authfail";
			} else {
			
			System.out.println("SETTING SESSION ID" + sealSessionId);
				return "redirect:/saml/login?session=" + sealSessionId;
			//}
		} else {
			LOG.error("Something wrong with the SM session: " + resp.getError());
			redirectAttrs.addFlashAttribute("errorMsg", "Error validating token! " + resp.getError());
		}

		return "redirect:/saml/login";
	}
}

