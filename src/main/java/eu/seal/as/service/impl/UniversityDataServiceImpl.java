/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.as.model.pojo.UniversityData;
import eu.seal.as.service.ParameterService;
import eu.seal.as.service.UniversityDataService;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 *
 * @author nikos
 */
@Service
public class UniversityDataServiceImpl implements UniversityDataService {

    private ParameterService paramServ;
    private final static Logger log = LoggerFactory.getLogger(UniversityDataServiceImpl.class);
    ObjectMapper mapper;

    public UniversityDataServiceImpl(ParameterService paramServ) {
        this.paramServ = paramServ;
        this.mapper = new ObjectMapper();
    }

    @Override
    public Optional<UniversityData[]> getCodes() {
        String configFilePath = paramServ.getParam("UNIVERSITIES_CONFIG_PATH");
        try {
            InputStream is = new FileInputStream(configFilePath);
            return Optional.of(mapper.readValue(is, UniversityData[].class));
        } catch (Exception e) {
            log.error("error reading univ config file, path was " + configFilePath, e.getMessage());
            log.error(e.getMessage());
        }
        return Optional.empty();
    }

}
