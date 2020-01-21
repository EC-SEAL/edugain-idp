/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service.impl;

import eu.seal.as.model.pojo.GrantRequest;
import eu.seal.as.model.pojo.MinEduAmkaResponse;
import eu.seal.as.model.pojo.MinEduLog;
import eu.seal.as.model.pojo.MinEduResponse;
import eu.seal.as.model.pojo.TokenResponse;
import eu.seal.as.model.pojo.MinEduResponse.InspectionResult;
import eu.seal.as.service.MinEduService;
import eu.seal.as.service.ParameterService;
import eu.seal.as.utils.TimestampUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author nikos
 */
@Service
public class MinEduServiceImpl implements MinEduService {

    private ParameterService paramServ;
    private final String minEduTokenUri;
    private final String minEduTokenUser;
    private final String minEduTokenPass;
    private final String minEduTokenGrantType;
    private final String minEduQueryIdEndpoint;
    private final String minEduQueryByAmkaEndpoint;
    private LocalDateTime accessTokenExpiration;
    private Optional<String> activeToken;

    private final static Logger LOG = LoggerFactory.getLogger(MinEduServiceImpl.class);

    @Autowired
    public MinEduServiceImpl(ParameterService paramServ) {
        this.paramServ = paramServ;
        this.minEduTokenUri = paramServ.getParam("MINEDU_TOKEN_URL");
        this.minEduTokenPass = paramServ.getParam("MINEDU_TOKEN_PASSWORD");
        this.minEduTokenUser = paramServ.getParam("MINEDU_TOKEN_USERNAME");
        this.minEduTokenGrantType = paramServ.getParam("MINEDU_TOKEN_GRANTTYPE");
        this.minEduQueryIdEndpoint = paramServ.getParam("MINEDU_QUERYID_URL");
        this.minEduQueryByAmkaEndpoint = paramServ.getParam("MINEDU_QUERY_BY_AMKA"); //https://gateway.interoperability.gr/academicId/1.0.1/student/
        this.accessTokenExpiration = LocalDateTime.now();
        this.activeToken = Optional.empty();
    }

    @Override
    public Optional<String> getAccessToken() {
        GrantRequest grantReq = new GrantRequest(minEduTokenUser, minEduTokenPass, minEduTokenGrantType);
        RestTemplate restTemplate = new RestTemplate();
        LOG.info("will get toke from theurl: " + minEduTokenUri);

        try {
            if (activeToken.isPresent() && accessTokenExpiration.isAfter(LocalDateTime.now().plusSeconds(30))) {
                LOG.info("MinEdu OAth token still alive " + activeToken.get());
                return activeToken;
            } else {
                LOG.info("will get new token ");
                TokenResponse tokResp = restTemplate.postForObject(minEduTokenUri, grantReq, TokenResponse.class);
                if (tokResp != null && tokResp.getSuccess().equals("true") && tokResp.getOauth() != null && tokResp.getOauth().getAccessToken() != null) {
                    LOG.info("retrieved token " + tokResp.getOauth().getAccessToken());
                    this.accessTokenExpiration = this.accessTokenExpiration.plusSeconds(tokResp.getOauth().getExpiresIn());
                    this.activeToken = Optional.of(tokResp.getOauth().getAccessToken());
                    return this.activeToken;
                }
                LOG.error(tokResp.getError().getMessage().toString());
            }

        } catch (HttpClientErrorException e) {
            LOG.error(e.getMessage());
        }

        return Optional.empty();
    }

    @Override
    public Optional<InspectionResult> getInspectioResultByAcademicId(String academicId, String selectedUniversityId, String esmoSessionId) {
        String minEduQueryIdUrl = this.minEduQueryIdEndpoint + "?id=" + academicId + "&username=" + this.minEduTokenUser + "&password=" + this.minEduTokenPass;
        HttpHeaders requestHeaders = new HttpHeaders();
        Optional<String> accessToken = getAccessToken();
        if (accessToken.isPresent()) {
            RestTemplate restTemplate = new RestTemplate();
            requestHeaders.add("Authorization", "Bearer " + accessToken.get());
            HttpEntity<?> entity = new HttpEntity<>(requestHeaders);
            LOG.info("querying for academicId " + academicId);
            try {
                ResponseEntity<MinEduResponse> queryId = restTemplate.exchange(minEduQueryIdUrl, HttpMethod.GET, entity, MinEduResponse.class);
                MinEduResponse qResp = queryId.getBody();
                InspectionResult ir = qResp.getResult().getInspectionResult();
                MinEduLog logEntry = new MinEduLog(qResp.getServiceCallID(), selectedUniversityId, qResp.getTimestamp(), TimestampUtils.getIso8601Date(), esmoSessionId);
                LOG.info("MinEduLog " + logEntry.toString());
                return Optional.of(ir);
            } catch (HttpClientErrorException e) {
                LOG.error(e.getMessage());
            }

        }
        LOG.error("no token found in response!");
        return Optional.empty();
    }

    @Override
    public Optional<String> getAcademicIdFromAMKA(String amkaNumber, String selectedUniversityId, String esmoSessionId) {
        String requestUrl = this.minEduQueryByAmkaEndpoint + "/" + amkaNumber + "?fields=academicID&username=" + this.minEduTokenUser + "&password=" + this.minEduTokenPass;
        HttpHeaders requestHeaders = new HttpHeaders();
        Optional<String> accessToken = getAccessToken();
        if (accessToken.isPresent()) {
            LOG.info("querying for amka " + amkaNumber);
            LOG.info("will query amka in theurl: " + requestUrl);
            RestTemplate restTemplate = new RestTemplate();
            requestHeaders.add("Authorization", "Bearer " + accessToken.get());
            HttpEntity<?> entity = new HttpEntity<>(requestHeaders);
            try {
                ResponseEntity<MinEduAmkaResponse> queryResponse = restTemplate.exchange(requestUrl, HttpMethod.GET, entity, MinEduAmkaResponse.class);
                LOG.info("result " + queryResponse.getBody().getResult().getAcademicID());
                MinEduLog logEntry = new MinEduLog(queryResponse.getBody().getServiceCallID(), selectedUniversityId, queryResponse.getBody().getTimestamp(), TimestampUtils.getIso8601Date(), esmoSessionId);
                LOG.info("MinEduLog " + logEntry.toString());

                if (queryResponse.getBody().isSuccess()) {
                    if (queryResponse.getBody().getResult() != null && queryResponse.getBody().getResult().getAcademicID() != null) {
                        return Optional.of(queryResponse.getBody().getResult().getAcademicID());
                    }
                    LOG.error("no acadmic id found for amka " + amkaNumber);
                }
            } catch (HttpClientErrorException e) {
                LOG.error(e.getMessage());
            }
        }
        LOG.error("no token found in response!");
        return Optional.empty();
    }

    @Override
    public Optional<MinEduResponse> getInspectioResponseByAcademicId(String academicId, String selectedUniversityId, String esmoSessionId) {
        String minEduQueryIdUrl = this.minEduQueryIdEndpoint + "?id=" + academicId + "&username=" + this.minEduTokenUser + "&password=" + this.minEduTokenPass;
        HttpHeaders requestHeaders = new HttpHeaders();
        Optional<String> accessToken = getAccessToken();
        if (accessToken.isPresent()) {
            RestTemplate restTemplate = new RestTemplate();
            requestHeaders.add("Authorization", "Bearer " + accessToken.get());
            HttpEntity<?> entity = new HttpEntity<>(requestHeaders);
            LOG.info("querying for academicId " + academicId);
            try {
                ResponseEntity<MinEduResponse> queryId = restTemplate.exchange(minEduQueryIdUrl, HttpMethod.GET, entity, MinEduResponse.class);
                MinEduResponse qResp = queryId.getBody();
                MinEduLog logEntry = new MinEduLog(qResp.getServiceCallID(), selectedUniversityId, qResp.getTimestamp(), TimestampUtils.getIso8601Date(), esmoSessionId);
                LOG.info("MinEduLog " + logEntry.toString());
                return Optional.of(qResp);
            } catch (HttpClientErrorException e) {
                LOG.error(e.getMessage());
            }
        }
        LOG.error("no token found in response!");
        return Optional.empty();
    }

}
