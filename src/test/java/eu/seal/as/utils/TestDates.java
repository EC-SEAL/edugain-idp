/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.utils;

import java.text.ParseException;
import java.util.Date;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

import eu.seal.as.utils.DateParsingUtils;
import eu.seal.as.utils.TimestampUtils;

/**
 *
 * @author nikos
 */
public class TestDates {

    @Test
    public void testAmkaDate() throws ParseException {
        Date d = DateParsingUtils.parseAmkaDate("05108304675");
        assertEquals(d.getDate(), 5);
        assertEquals(d.getMonth() + 1, 10); // get month returns 0 for january
        assertEquals(d.getYear() + 1900, 1983); //get year returns year - 1900
    }

    @Test
    public void testEidasDate() throws ParseException {
        String date = "1980-01-01";
        Date d = DateParsingUtils.parseEidasDate(date);
        assertEquals(d.getDate(), 1);
        assertEquals(d.getMonth() + 1, 1); // get month returns 0 for january
        assertEquals(d.getYear() + 1900, 1980); //get year returns year - 1900

    }

    @Test
    public void testDateEquality() throws ParseException {
        Date d1 = DateParsingUtils.parseAmkaDate("01018004675");
        String date = "1980-01-01";
        Date d2 = DateParsingUtils.parseEidasDate(date);

        assertEquals(d1.compareTo(d2), 0);

    }
    
    @Test
    public void testTimestampByMinEdu(){
        System.out.println(TimestampUtils.getIso8601Date());
    
    }

}
