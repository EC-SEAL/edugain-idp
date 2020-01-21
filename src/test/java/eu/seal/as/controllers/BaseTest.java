package eu.seal.as.controllers;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.mockserver.integration.ClientAndServer;

public class BaseTest {
    
    private static ClientAndServer mockServer;

    
    @BeforeClass
    public static void setupMockServer() throws IOException, JAXBException {
        mockServer = ClientAndServer.startClientAndServer(8000);
        
        Expectations.createDefaultExpectations(mockServer);
    }

    @AfterClass
    public static void after() {
        mockServer.stop();
    }

}