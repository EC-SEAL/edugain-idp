/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service.impl;

import java.util.List;
import java.util.Optional;
import org.opensaml.saml2.core.Attribute;

/**
 *
 * @author nikos
 */
public class SamlUtils {

    public static Optional<Attribute> getByFriendlyName(List<Attribute> attributes, String friendlyName) {
        return attributes.stream().filter(attr -> {
            return attr.getFriendlyName().equals(friendlyName);
        }).findFirst();
    }

}
