/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.idp;



import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import eu.seal.idp.model.pojo.DataSet;
import eu.seal.idp.model.pojo.DataStore;
import eu.seal.idp.service.impl.DataStoreServiceImpl;


@RunWith(SpringRunner.class)
public class TestDataStoreService {

	// Given a Datastore with one item, pushing a dataset, the size increases
    @Test
    public void testPush() {
    	
    	// **** UNNECESSARY
    	
    	DataStore dataStore = new DataStore();
        DataStoreServiceImpl dataStoreService = new DataStoreServiceImpl();
        DataSet initialDataSet = new DataSet();
        DataSet appendedDataSet = new DataSet();
        List <DataSet> dsArrayList = new ArrayList();
	
        initialDataSet.setId("1");
        appendedDataSet.setId("2");
        
		dsArrayList.add(initialDataSet);
        dataStore.setClearData(dsArrayList);
        System.out.println("DataStore before: " + dataStore);
        
        dataStore = dataStoreService.pushDataSet(dataStore, appendedDataSet);
        System.out.println("DataStore after: " + dataStore);
		
        assertEquals(dataStore.getClearData().size(), 2);

    }

}