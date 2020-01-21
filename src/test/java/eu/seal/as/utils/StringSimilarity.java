/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.utils;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

import eu.seal.as.utils.StringDistance;

/**
 *
 * @author nikos
 */
public class StringSimilarity {

    @Test
    public void testStrings() {

        String word1 = "Kavassalis";
        String word2 = "Kavasalis";
        assertEquals(StringDistance.areSimilar(word1, word2), true);
       

        word1 = "Ksystra";
        word2 = "Xystra";
        assertEquals(StringDistance.areSimilar(word1, word2), true);
       

        word1 = "Triantafyllou";
        word2 = "Triadafyllou";
        assertEquals(StringDistance.areSimilar(word1, word2), true);
      

        word1 = "Triantafyllou";
        word2 = "Triadafylloy";
        assertEquals(StringDistance.areSimilar(word1, word2), true);
       
        word1 = "Triantafylou";
        word2 = "Triadafyllou";
        assertEquals(StringDistance.areSimilar(word1, word2), true);
        

        word1 = "Triantafyllou";
        word2 = "Triadafilloy";
        assertEquals(StringDistance.areSimilar(word1, word2), true);
        

        word1 = "Kalapalis";
        word2 = "Kavassalis";
        assertEquals(StringDistance.areSimilar(word1, word2), true);
       
        word1 = "Nikolaos";
        word2 = "NIKOLAOS";
        assertEquals(StringDistance.areSimilar(word1, word2), true);
        

    }

}
