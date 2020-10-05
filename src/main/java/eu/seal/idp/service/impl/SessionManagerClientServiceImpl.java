package eu.seal.idp.service.impl;

import java.io.IOException;
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

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.idp.model.pojo.NewUpdateDataRequest;
import eu.seal.idp.model.pojo.SessionMngrResponse;
import eu.seal.idp.model.pojo.UpdateDataRequest;
import eu.seal.idp.service.HttpSignatureService;
import eu.seal.idp.service.KeyStoreService;
import eu.seal.idp.service.NetworkService;
import eu.seal.idp.service.SessionManagerClientService;

public class SessionManagerClientServiceImpl implements SessionManagerClientService {
	
	private final static Logger LOG = LoggerFactory.getLogger(SessionManagerClientServiceImpl.class);
	private final String URIVALIDATE = "/sm/validateToken";
	private final String URIGETSESSION = "/sm/getSessionData";
	private final String URIUPDATESESSION = "/sm/updateSessionData";
	private final String URIUPDATENEWSESSION = "/sm/new/add";
	
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
	
	
	
	/**
	 * Generates a token to call a ms
	 * @param id SessionID
	 * @param sender Sender ms identifier
	 * @param receiver "" ms identifier
	 * @return Session Manager response of getting this value from the SM
	 */
	
	public SessionMngrResponse generateToken(String id, String sender, String receiver) {
		ArrayList<NameValuePair> reqParams = new ArrayList<NameValuePair>();
		reqParams.add(new NameValuePair("sessionId", id));
		reqParams.add(new NameValuePair("sender", sender)); 
		reqParams.add(new NameValuePair("receiver", receiver)); 
		String clearRespGet;
		try {
			clearRespGet = netServ.sendGet(sessionMngrURL, "/sm/generateToken", reqParams, 1);
			return mapper.readValue(clearRespGet, SessionMngrResponse.class);
		} catch (NoSuchAlgorithmException | IOException e1) {
			e1.printStackTrace();
		}
		return null;
	}
	
	

	/**
	 * Validates a token
	 * @param id SessionID
	 * @param sender Sender ms identifier
	 * @param receiver "" ms identifier
	 * @return Session Manager response of getting this value from the SM
	 */
	
	public SessionMngrResponse validateToken(String msToken) {
		SessionMngrResponse resp = new SessionMngrResponse();
		try {
			List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
			requestParams.add(new NameValuePair("token", msToken));
			String rspValidate = netServ.sendGet(sessionMngrURL, URIVALIDATE, requestParams, 1);
			resp = mapper.readValue(rspValidate, SessionMngrResponse.class);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return resp;
	}
	
	/**
	 * Calls the session manager with am arrayList of requestParams
	 * @param reqParams An ArrayList of NameValuePair that will be used as request params 
	 */
	
	public SessionMngrResponse getParams(ArrayList<NameValuePair> reqParams) {
		try {
			String clearRespGet = netServ.sendGet(sessionMngrURL, URIGETSESSION, reqParams, 1);
			SessionMngrResponse respGet;
			respGet = mapper.readValue(clearRespGet, SessionMngrResponse.class);
			return respGet;
		} catch (Exception e) {
			e.printStackTrace();
			return new SessionMngrResponse();
		}
	}
	
	/**
	 * Calls the session manager with a single NameValuePair
	 * @param key The key of the NameValue
	 * @param value The value of the  NameValuePair
	 * @return SessionMngrResponse The response from the SM
	 */
	
	public SessionMngrResponse getSingleParam(String key, String value) {
		ArrayList<NameValuePair> reqParams = new ArrayList<NameValuePair>();
		reqParams.add(new NameValuePair(key, value));
		return getParams(reqParams);
	}
	
	/**
	 * Updates a session Variable
	 * @param key The key of the NameValue
	 * @param value The value of the  NameValuePair
	 * @return SessionMngrResponse The response from the SM
	 */
	
	public String updateSessionVariables(String sessionId, String objectId, String variableName, Object updateObject) throws IOException, NoSuchAlgorithmException {
        ObjectMapper mapper = new ObjectMapper();
        String stringifiedObject = mapper.writeValueAsString(updateObject);

        UpdateDataRequest updateReq = new UpdateDataRequest(sessionId, variableName, stringifiedObject);
        SessionMngrResponse resp = mapper.readValue(netServ.sendPostBody(sessionMngrURL, URIUPDATESESSION, updateReq, "application/json", 1), SessionMngrResponse.class);
        LOG.info("updateSessionData " + resp.getCode().toString());
        if (!resp.getCode().toString().equals("OK")) {
            LOG.error("ERROR: " + resp.getError());
            return "error";
        }
        LOG.info("session " + sessionId + " updated LEGACY API Session succesfully  with user attributes " + stringifiedObject);

        if (variableName.equals("dsResponse")) {
            NewUpdateDataRequest newReq = new NewUpdateDataRequest();
            newReq.setId(objectId);
            newReq.setSessionId(sessionId);
            newReq.setType("dataSet");
            newReq.setData(stringifiedObject);
            String result = netServ.sendNewPostBody(sessionMngrURL, URIUPDATENEWSESSION, newReq, "application/json", 1);
            
            System.out.println("Result" + result);
            resp = mapper.readValue(result, SessionMngrResponse.class);
            LOG.info("updateSessionData " + resp.getCode().toString());
            if (!resp.getCode().toString().equals("OK")) {
                LOG.error("ERROR: " + resp.getError());
                return "error";
            }
            LOG.info("session " + sessionId + " updated NEW API Session succesfully  with objectID" + objectId + "  with user attributes " + stringifiedObject);
        }

        return "ok";
    }
	
	/**
	 * Gets the dataStore session variable
	 * Returns the list of dataSet/linkRequest objects from the DataStore.
	 * If type is null, returns the complete DataStore.
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 */	
	
	public Object getDataStore(String sessionId, String type) throws NoSuchAlgorithmException, IOException {
		
		String sessionMngrUrl = System.getenv("SESSION_MANAGER_URL");
		List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
		requestParams.add(new NameValuePair("sessionId", sessionId));
		requestParams.add(new NameValuePair("type", type));
		
		SessionMngrResponse rsp = netServ.sendGetSMResponse(sessionMngrUrl, "/sm/new/get",requestParams, 1);
		
		LOG.info("dataStore: " + rsp.getAdditionalData());
		return rsp.getAdditionalData();
	}
	
	
	/**
	 * Updates the dataStore session Variable
	 */	
	
	public String updateDatastore(String sessionId, String objectId, Object updateObject) throws IOException, NoSuchAlgorithmException {
        ObjectMapper mapper = new ObjectMapper();
        String stringifiedObject = mapper.writeValueAsString(updateObject);

            NewUpdateDataRequest newReq = new NewUpdateDataRequest();
            newReq.setId(objectId);
            newReq.setSessionId(sessionId);
            newReq.setType("dataSet");
            newReq.setData(stringifiedObject);
            String result = netServ.sendNewPostBody(sessionMngrURL, URIUPDATENEWSESSION, newReq, "application/json", 1);
            
            LOG.info("Result" + result);          
            LOG.info("session " + sessionId + " updated NEW API Session succesfully  with objectID" + objectId + "  with user attributes " + stringifiedObject);

        return "ok";
    }
	
	
}
