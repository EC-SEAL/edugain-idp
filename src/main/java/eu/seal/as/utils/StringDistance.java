/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.utils;

import info.debatty.java.stringsimilarity.CharacterSubstitutionInterface;
import info.debatty.java.stringsimilarity.JaroWinkler;
import info.debatty.java.stringsimilarity.Levenshtein;
import info.debatty.java.stringsimilarity.NGram;
import info.debatty.java.stringsimilarity.WeightedLevenshtein;

/**
 *
 * @author nikos
 */
public class StringDistance {

    public static boolean areSimilarLevhestine(String word1, String word2, double threshold) {
        JaroWinkler jw = new JaroWinkler();
        double result = jw.similarity(word1, word2);
        System.out.println("JW: " + result);
        return result > threshold;
    }

    // abcdefghijklmopqrstuvwxyz
    //αβγδεζηθικλμνξοπρστυφχξω
    public static double weightedDistance(String word1, String word2) {

        WeightedLevenshtein wl = new WeightedLevenshtein(
                new CharacterSubstitutionInterface() {
            public double cost(char c1, char c2) {

                // The cost for substituting 't' and 'r' is considered
                // smaller as these 2 are located next to each other
                // on a keyboard
                if (c1 == 'i' && c2 == 'y') {
                    return 0;
                }
                
                if (c1 == 'u' && c2 == 'y') {
                    return 0;
                }
                
                if (c1 == 'i' && c2 == 'e') {
                    return 0;
                }
                if (c1 == 'v' && c2 == 'b') {
                    return 0;
                }

                // For most cases, the cost of substituting 2 characters
                // is 1.0
                return 1.0;
            }
        });

        System.out.println("comparing: "  + word1 + " " + word2);
        System.out.println("result: " + wl.distance(word1, word2));
        
        return wl.distance(word1, word2);

    }

    public static boolean areSimilarNG(String word1, String word2, double threshold) {
        NGram twogram = new NGram(4);
        double result = twogram.distance(word1, word2);
        System.out.println("NG: " + result);

        return 1 - result > threshold;
    }

    public static double getLevDistance(String word1, String word2) {
        Levenshtein l = new Levenshtein();
        double result = l.distance(word1, word2);
        System.out.println("Dist: " + result);
        return result;
    }

    public static boolean areSimilar(String word1, String word2) {
        return areSimilarLevhestine(word1.toLowerCase(), word2.toLowerCase(), 0.7) && weightedDistance(word1.toLowerCase(), word2.toLowerCase()) < 4;

    }

}
