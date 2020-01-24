package eu.seal.as.controllers;

import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.JsonBody;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import eu.seal.as.model.pojo.SessionMngrResponse;

public class Expectations {

	private static Gson gson = new Gson();

	public static void createDefaultExpectations(ClientAndServer mockServer) {
		// GET
		getProduct(mockServer);

	}


	private static void getProduct(ClientAndServer mockServer) {
		String   products [] = new String[1];
		products[0]="blahba";
		String fileName = "mocks/sm_response_ap.json";
        File file = new File(Expectations.class.getClassLoader().getResource(fileName).getFile());
        List<String> content;
        try {
        	ObjectMapper mapper = new ObjectMapper();  
        	SessionMngrResponse response = mapper.readValue(file, SessionMngrResponse.class);
        	mockServer.when(request().withMethod("GET").withPath("/sm/validateToken"))
			.respond(response().withStatusCode(200).withBody(gson.toJson(response)));
        	
        } catch (IOException e) {
        	e.printStackTrace();
        }
        
	}

}