package eu.seal.idp.service;

import eu.seal.idp.model.pojo.SessionMngrResponse;

public interface SessionManagerClientService {
	public SessionMngrResponse validateToken(String msToken);
	public SessionMngrResponse getSingleParam(String key, String value);
}
