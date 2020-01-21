/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service;

import java.util.Optional;

import eu.seal.as.model.pojo.UniversityData;

/**
 *
 * @author nikos
 */
public interface UniversityDataService {
    
    
    public Optional<UniversityData[]> getCodes();
    
}
