
package eu.seal.idp.controllers;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.idp.model.pojo.EntityMetadata;
import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.service.SealMetadataService;
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
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.slf4j.Logger;	
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Controllers managing Seal Authentication Source, used in the log in and SSO Callback
 *  */

@Controller
public class RequestController {

	private final static Logger LOG = LoggerFactory.getLogger(RequestController.class);

	private final NetworkService netServ;
	private final KeyStoreService keyServ;
	private final SealMetadataService metadataServ;

	@Autowired
	public RequestController(KeyStoreService keyServ,
			SealMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
		this.keyServ = keyServ;
		this.metadataServ=metadataServ;
		Key signingKey = this.keyServ.getSigningKey();
		String fingerPrint = this.keyServ.getFingerPrint();
		HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
		this.netServ = new NetworkServiceImpl(httpSigServ);
	}

	/**
	 * Redirects an existing AP request to the IDP 
	 * @param msToken
	 * @param model
	 * @param redirectAttrs
	 * @return redirect :/saml/login (success) or :/authfail
	 * @throws KeyStoreException
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws JsonMappingException 
	 * @throws JsonParseException 
	 */

	@RequestMapping(value = {"/is/query", "as/authenticate"}, method = { RequestMethod.POST, RequestMethod.GET})
	public String query(@RequestParam(value = "msToken", required = true) String msToken, RedirectAttributes redirectAttrs, HttpServletRequest request, HttpServletResponse response) throws KeyStoreException, JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		
		EntityMetadata metadata = this.metadataServ.getMetadata();
		String stringifiedMetadata = mapper.writeValueAsString(metadata);
		
		LOG.info(stringifiedMetadata);	
		
		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("token", msToken));
	
		String rspValidate = netServ.sendGet(sessionMngrUrl, "/sm/validateToken", requestParams, 1);
		SessionMngrResponse resp = mapper.readValue(rspValidate, SessionMngrResponse.class);
		if (resp.getCode().toString().equals("OK") && StringUtils.isEmpty(resp.getError())) {
			String sealSessionId = resp.getSessionData().getSessionId();
			if(sealSessionId == null || sealSessionId.isEmpty()) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "session is null");
				return null;
			}
			request.getSession().setAttribute("path", request.getPathInfo());
			//LOG.info("path: ", request.getPathInfo());
			LOG.info("path: ", request.getRequestURI());
			String redirectUri = "/saml/login?session=" + sealSessionId + 
					"&callback=/"+ ((request.getRequestURI().contains("authenticate")) ?"callback" : "callbackq");
			
			LOG.info("About to redirect to" + redirectUri);
			return "redirect:" + redirectUri;
		} else {
			LOG.error("Error validating token");
			redirectAttrs.addFlashAttribute("errorMsg", "Error validating token! " + resp.getError());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error validating token! " + resp.getError());
			return null;
		}
	}
}

