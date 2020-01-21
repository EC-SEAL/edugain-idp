/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.utils;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

import eu.seal.as.utils.TranslitarateUtils;

/**
 *
 * @author nikos
 */
public class TestLanguateConvertion {

    @Test
    public void gr2en() {
        String department = "ΜΗΧΑΝΙΚΩΝ ΟΙΚΟΝΟΜΙΑΣ ΚΑΙ ΔΙΟΙΚΗΣΗΣ (ΠΑΝΕΠΙΣΤΗΜΙΟ ΑΙΓΑΙΟΥ)";
        System.out.println(TranslitarateUtils.convertGreektoLatin(department));
        String oxi = "ΟΧΙ";
//        System.out.println(TranslitarateUtils.convertGreektoLatin(oxi));
        assertEquals(TranslitarateUtils.convertGreektoLatin(oxi), "NO");
//        System.out.println(TranslitarateUtils.convertGreektoLatin("ΝΑΙ"));
        assertEquals(TranslitarateUtils.convertGreektoLatin("ΝΑΙ"), "YES");

    }

    @Test
    public void getLatinNameFromEidas() {
        String value = "Τριανταφύλλου, Triantafyllou";

//        System.out.println(TranslitarateUtils.getLatinFromMixed(value));
        assertEquals(TranslitarateUtils.getLatinFromMixed(value), "TRIANTAFYLLOU");

        value = "Triantafyllou";
        assertEquals(TranslitarateUtils.getLatinFromMixed(value), "TRIANTAFYLLOU");

        value = "Triantafyllou Delonga";
        assertEquals(TranslitarateUtils.getLatinFromMixed(value), "TRIANTAFYLLOU DELONGA");

    }

}
