package eu.seal.idp.model.factories;


import java.util.List;
import java.util.stream.Collectors;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;

import eu.seal.idp.model.pojo.AttributeType;


public class AttributeTypeFactory {


    public static AttributeType[] makeFromSamlAttribute(List<Attribute> attributes) {
        AttributeType[] result = new AttributeType[attributes.size()];
        return attributes.stream().map(attr -> {
            AttributeType type = new AttributeType();
            type.setEncoding("en");
            type.setFriendlyName(attr.getFriendlyName());
            type.setMandatory(true);
            type.setLanguage("en");

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