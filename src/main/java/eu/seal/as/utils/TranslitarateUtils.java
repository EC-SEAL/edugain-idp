/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.utils;

import java.util.Arrays;
import java.util.StringJoiner;
import java.util.regex.Pattern;
import net.gcardone.junidecode.Junidecode;

/**
 *
 * @author nikos
 */
public class TranslitarateUtils {

    private static final Pattern isLatin = Pattern.compile("[A-Za-z]+");

    public static String convertGreektoLatin(String greekText) {
        String res = Junidecode.unidecode(greekText);
        switch (res) {
            case "OKhI":
                return "NO";
            case "NAI":
                return "YES";
            default:
                return res;
        }
    }

    public static String getLatinFromMixed(String mixedText) {
        StringJoiner joiner = new StringJoiner(" ");
        String[] words = mixedText.split(",");
        Arrays.stream(words).forEach(word -> {
            Arrays.stream(word.split(" ")).forEach(w -> {
                if (isLatin.matcher(w).find()) {
                    joiner.add(w);
                }
            });

        });

        return joiner.toString().toUpperCase();
    }

}
