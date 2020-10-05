package eu.seal.idp.service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.apache.commons.httpclient.NameValuePair;

import eu.seal.idp.model.pojo.SessionMngrResponse;



public interface NetworkService {

    public String sendGet(String hostUrl, String uri, List<NameValuePair> urlParameters, int attempt) throws IOException, NoSuchAlgorithmException;

    public String sendPostForm(String hostUrl, String uri, List<NameValuePair> urlParameters, int attempt) throws IOException, NoSuchAlgorithmException;

    public String sendPostBody(String hostUrl, String uri, Object postBody, String contentType, int attempt) throws IOException, NoSuchAlgorithmException;

	String sendNewPostBody(String hostUrl, String uri, Object postBody, String contentType, int attempt)
			throws IOException, NoSuchAlgorithmException;
	
	public SessionMngrResponse sendGetSMResponse(String hostUrl, String uri, List<NameValuePair> urlParameters, int attempt) 
			throws IOException, NoSuchAlgorithmException;

}
