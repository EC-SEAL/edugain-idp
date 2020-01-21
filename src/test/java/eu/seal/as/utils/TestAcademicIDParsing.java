/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.utils;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.as.model.pojo.MinEduResponse;

import java.io.IOException;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 *
 * @author nikos
 */
public class TestAcademicIDParsing {

    @Test
    public void testParsingResponse() throws IOException {
        String testResp = "{\n"
                + "  \"ServiceCallID\": \"b595e4df-72ea-41bb-80a7-d81d41784da9\",\n"
                + "  \"code\": 200,\n"
                + "  \"success\": true,\n"
                + "  \"Result\": {\n"
                + "    \"inspectionResult\": {\n"
                + "      \"departmentName\": \"ΜΗΧΑΝΙΚΩΝ ΟΙΚΟΝΟΜΙΑΣ ΚΑΙ ΔΙΟΙΚΗΣΗΣ (ΠΑΝΕΠΙΣΤΗΜΙΟ ΑΙΓΑΙΟΥ)\",\n"
                + "      \"entryYear\": 2014,\n"
                + "      \"studentshipType\": \"Προπτυχιακός\",\n"
                + "      \"currentSemester\": 3,\n"
                + "      \"cancellationReason\": \"Δεν έχει ακυρωθεί\",\n"
                + "      \"erasmus\": \"Όχι\",\n"
                + "      \"studentNumber\": \"2312014103\",\n"
                + "      \"residenceLocation\": \"ΣΑΜΟΥ - ΣΑΜΟΥ\",\n"
                + "      \"pasoExpirationDate\": \"31/08/2021\",\n"
                + "      \"submissionDate\": \"22/10/2015\",\n"
                + "      \"postGraduateProgram\": \"\",\n"
                + "      \"greekFirstName\": \"ΜΑΡΙΑ\",\n"
                + "      \"validationError\": null,\n"
                + "      \"amka\": null,\n"
                + "      \"photoUrl\": \"/9j/4AAQSkZJRgABAQEBLAEsAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0a\\r\\nHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIy\\r\\nMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCADsAOwDASIA\\r\\nAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA\\r\\nAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3\\r\\nODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWm\\r\\np6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEA\\r\\nAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSEx\\r\\nBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElK\\r\\nU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3\\r\\nuLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD2pDiJ\\r\\nfpS5pg6AelLXUloZPcfmkzTaTNFgH596TNJSU7ALmim0maLAPzSZpuaT6U7AOzRnioZZ44VZncAL\\r\\n1rn73xTArGOB146ux/pVKDYrnSZ96TdXEt4tPT7QM59KZceNXgKogWQkfeNWqd+oXO53fSjcM9a8\\r\\n2Pj27L/dUc9hVa48Y6nOT5cgjHtS5Et2JNvoepbhRu/D8a8hj8T6hAxJunJPqavp4/vlC5CNj1HW\\r\\nmoRezHdroen7qTNcBa/EDc4E8S49Qa6Cy8U6fe4AkCMezGjkYXN7NGfeoUlSRQysCD3Bp+am1hj8\\r\\n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\\r\\nEbEIK6IYl2tLUp4aP2dD/9k=\\r\\n\",\n"
                + "      \"pasoValidity\": \"Ναι\",\n"
                + "      \"applicationStatus\": \"Η Ακαδημαϊκή Ταυτότητα παραδόθηκε στο δικαιούχο\",\n"
                + "      \"academicId\": \"273004078833\",\n"
                + "      \"latinFirstName\": \"MARIA\",\n"
                + "      \"latinLastName\": \"PAPAGEORGIOU\",\n"
                + "      \"universityLocation\": \"ΧΙΟΥ - ΧΙΟΥ\",\n"
                + "      \"greekLastName\": \"ΠΑΠΑΓΕΩΡΓΙΟΥ\",\n"
                + "      \"webServiceSuccess\": true,\n"
                + "      \"cancellationDate\": \"\"\n"
                + "    },\n"
                + "    \"response\": \"SUCCESS\",\n"
                + "    \"errorReason\": null\n"
                + "  },\n"
                + "  \"timestamp\": \"2019-04-08T15:57:00+03:00\"\n"
                + "}";
        
        ObjectMapper mapper = new ObjectMapper();
        
        MinEduResponse resp = mapper.readValue(testResp, MinEduResponse.class);
        
        assertEquals(resp.getServiceCallID(),"b595e4df-72ea-41bb-80a7-d81d41784da9");
        assertEquals(resp.getResult().getInspectionResult().getAcademicId(),"273004078833");
        

    }

}
