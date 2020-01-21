/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service;

import eu.seal.as.service.MinEduService;
import eu.seal.as.service.ParameterService;
import eu.seal.as.service.impl.MinEduServiceImpl;

import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.springframework.beans.factory.annotation.Autowired;

/**
 *
 * @author nikos
 */
//@RunWith(SpringRunner.class)
//@SpringBootTest
public class TestMinEduService {

    @Autowired
    ParameterService paramServ;

    private MinEduService serv;

    @Before
    public void init() {
        this.serv = new MinEduServiceImpl(paramServ);
    }

//    @Test
    public void testGetByAmka() {
        System.out.println(this.serv.getAcademicIdFromAMKA("05108304675", "", "esmoSession"));
        assertEquals(this.serv.getAcademicIdFromAMKA("05108304675", "", "esmoSession").get(), "200260674408");
    }

//    @Test
    public void testGetByAcademicId() {
        System.out.println(this.serv.getInspectioResponseByAcademicId("200260674408", "", "esmoSession").get().getResult().getInspectionResult().getDepartmentName());
        assertEquals(this.serv.getInspectioResponseByAcademicId("200260674408", "", "esmoSession").get().getResult().getInspectionResult().getLatinLastName(), "Triantafyllou".toUpperCase());

    }
}
