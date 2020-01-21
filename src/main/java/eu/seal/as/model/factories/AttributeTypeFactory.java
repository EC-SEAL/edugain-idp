/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.model.factories;

import java.util.List;
import java.util.stream.Collectors;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;

import eu.seal.as.model.pojo.AttributeType;

/**
 *
 * @author nikos
 */
public class AttributeTypeFactory {

    /*
     private String name;
    private String friendlyName;
    private String encoding;
    private String language;
    private boolean isMandatory;
    private String[] values;
     */
    public static AttributeType[] makeFromSamlAttribute(List<Attribute> attributes) {
        AttributeType[] result = new AttributeType[attributes.size()];
        return attributes.stream().map(attr -> {
            AttributeType type = new AttributeType();
            type.setEncoding("en");
            type.setFriendlyName(attr.getFriendlyName());
            type.setIsMandatory(true);
            type.setLanguage("en");
//            type.setName(attr.getName()); leave name null because they do not match...

            if (attr.getAttributeValues().get(0) instanceof XSStringImpl) {
                type.setValues(new String[]{((XSStringImpl) attr.getAttributeValues().get(0)).getValue()});
            }

            if (attr.getAttributeValues().get(0) instanceof XSAnyImpl) {
                type.setValues(new String[]{((XSAnyImpl) attr.getAttributeValues().get(0)).getTextContent()});
            }

            return type;
        })
                .collect(Collectors.toList())
                .toArray(result);
    }

}
