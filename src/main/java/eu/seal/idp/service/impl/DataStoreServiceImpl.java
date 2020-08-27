package eu.seal.idp.service.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;


import eu.seal.idp.model.pojo.AttributeSet;
import eu.seal.idp.model.pojo.AttributeSet.TypeEnum;
import eu.seal.idp.model.pojo.AttributeSetStatus;
import eu.seal.idp.model.pojo.AttributeType;
import eu.seal.idp.model.pojo.DataSet;
import eu.seal.idp.model.pojo.DataStore;

@Service
public class DataStoreServiceImpl {
	
	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(SAMLDatasetDetailsServiceImpl.class);
	
	
	/**
	 * Push a new Dataset into an existing Datastore
	 * @param dStore
	 * @param dSet
	 * @return Modified Datastore
	 */
	
	public DataStore pushDataSet(DataStore dStore, DataSet dSet) {
		LOG.info("*** WHAT FOR?");
		
		List <DataSet> dsArrayList = new ArrayList();
		ObjectMapper mapper = new ObjectMapper();
		
		if(dStore.getClearData()!=null) {
			dsArrayList = dStore.getClearData();
		} else {
			LOG.info("No Dataset was found, creating a new DataStore");
			String datastoreId = UUID.randomUUID().toString();
			dStore.setId(datastoreId);
		}

		DataSet receivedDataset = dSet;
		dsArrayList.add(receivedDataset);
		dStore.setClearData(dsArrayList);
		return dStore;
		
	}
	
	public DataSet loadDatasetBySAML(String dsId, SAMLCredential credential)
			throws UsernameNotFoundException {
		
		DataSet dataset = new DataSet();
		dataset.setId(dsId);
		List<Attribute> attributesList = credential.getAttributes();
		
		for (Attribute att: attributesList) {
			AttributeType attributeType = new AttributeType();
			attributeType.setName(att.getName());
			attributeType.setFriendlyName(att.getFriendlyName());
			dataset.addAttributesItem(attributeType);
		}
		
		LOG.info(dataset.toString());
		return dataset;
	}
	

	
	
	
}
