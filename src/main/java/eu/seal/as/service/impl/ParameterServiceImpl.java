/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import eu.seal.as.service.ParameterService;

/**
 *
 * @author nikos
 */
@Service
public class ParameterServiceImpl implements ParameterService {

    private final Logger log = LoggerFactory.getLogger(ParameterServiceImpl.class);

//    private final Map<String, String> properties;
    public ParameterServiceImpl() {
//        properties = getConfigProperties();
    }

    @Override
    public String getParam(String paramName) {

        return System.getenv(paramName);
    }

}
