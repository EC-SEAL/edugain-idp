/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.model.factories;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.as.enums.TypeEnum;
import eu.seal.as.model.pojo.AttributeSet;
import eu.seal.as.model.pojo.AttributeSetStatus;
import eu.seal.as.model.pojo.AttributeType;
import eu.seal.as.model.pojo.EidasCurrentAddress;
import eu.seal.as.model.pojo.MinEduResponse;
import eu.seal.as.utils.TranslitarateUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author nikos
 */
public class EsmoResponseFactory {

    private final static Logger Log = LoggerFactory.getLogger(EsmoResponseFactory.class);

    public static AttributeSet buildErrorResponse(String issuer, String recipient, String smSessionId) {
        List<AttributeType> attributes = new ArrayList<>();
        String id = UUID.randomUUID().toString();
        Map< String, String> metadataProperties = new HashMap();
        AttributeSetStatus atrSetStatus = new AttributeSetStatus();
        atrSetStatus.setCode(AttributeSetStatus.CodeEnum.ERROR);
        AttributeType[] attrArray = new AttributeType[attributes.size()];
        return new AttributeSet(id, TypeEnum.Response, issuer, recipient,
                (AttributeType[]) attributes.toArray(attrArray), metadataProperties, smSessionId, "low", null, null, atrSetStatus);

    }

    public static AttributeSet buildFromMinEduResponse(MinEduResponse resp, String issuer, String recipient, String smSessionId, List<AttributeType> matchingAttributes) {

        if (resp.isSuccess()) {
            String id = UUID.randomUUID().toString();
            List<AttributeType> attributes = new ArrayList<>();
            String academicIdenitfier = resp.getResult().getInspectionResult().getAcademicId();
            String eduPersonAffiliation = TranslitarateUtils.convertGreektoLatin("student");
            String eduPersonAffiliationGR = "student";
            String primaryAffiliation = TranslitarateUtils.convertGreektoLatin("student");
            String primaryAffiliationGR = "student";
            String schacHomeOrganization = TranslitarateUtils.convertGreektoLatin(resp.getResult().getInspectionResult().getDepartmentName()).toUpperCase();
            String eduOrgLegalName = resp.getResult().getInspectionResult().getDepartmentName().toUpperCase();
            String cn = TranslitarateUtils.convertGreektoLatin(resp.getResult().getInspectionResult().getDepartmentName().toUpperCase());

            String email = "";
            String schacExpiryDate = "";
            String mobile = "";
            String eduPersonPrincipalName = "";
            String eduPersonPrincipalNamePrior = "";
            String displayName = resp.getResult().getInspectionResult().getLatinFirstName() + " " + resp.getResult().getInspectionResult().getLatinLastName();
            String sn = resp.getResult().getInspectionResult().getLatinFirstName() + "-" + resp.getResult().getInspectionResult().getLatinLastName();
            String univLocation = resp.getResult().getInspectionResult().getUniversityLocation();
            String givenName = resp.getResult().getInspectionResult().getLatinFirstName();

            attributes.add(new AttributeType("academicIdenitfier", "academicIdenitfier", "UTF-8", "en", false, (String[]) Arrays.asList(academicIdenitfier).toArray()));
            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonAffiliation", "eduPersonAffiliation", "UTF-8", "en", false, (String[]) Arrays.asList("student").toArray()));
            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrimaryAffiliation", "primaryAffiliation", "UTF-8", "en", false, (String[]) Arrays.asList("student").toArray()));
            // TODO complete attribute set???
//            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#mail", "mail", "UTF-8", "en", false, (String[]) Arrays.asList(email).toArray()));
//            attributes.add(new AttributeType("https://wiki.refeds.org/download/attachments/1606048/schac-20150413-1.5.0.schema.txt?version=1&modificationDate=1429044813839&api=v2#schacExpiryDate", "schacExpiryDate", "UTF-8", "en", false, (String[]) Arrays.asList(schacExpiryDate).toArray()));
//            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#mobile", "mobile", "UTF-8", "en", false, (String[]) Arrays.asList(mobile).toArray()));
//            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrincipalName", "eduPersonPrincipalName", "UTF-8", "en", false, (String[]) Arrays.asList(eduPersonPrincipalName).toArray()));
//            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrincipalNamePrior", "eduPersonPrincipalNamePrior", "UTF-8", "en", false, (String[]) Arrays.asList(eduPersonPrincipalNamePrior).toArray()));
            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#mail", "displayName", "UTF-8", "en", false, (String[]) Arrays.asList(displayName).toArray()));
            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#sn", "sn", "UTF-8", "en", false, (String[]) Arrays.asList(sn).toArray()));
            attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#givenName", "givenName", "UTF-8", "en", false, (String[]) Arrays.asList(givenName).toArray()));
            attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#eduOrgLegalName", "eduOrgLegalName", "UTF-8", "gr", false, (String[]) Arrays.asList(eduOrgLegalName).toArray()));
            attributes.add(new AttributeType("https://wiki.refeds.org/download/attachments/1606048/schac-20150413-1.5.0.schema.txt?version=1&modificationDate=1429044813839&api=v2#schacHomeOrganization", "schacHomeOrganization", "UTF-8", "en", false, (String[]) Arrays.asList(schacHomeOrganization).toArray()));
            attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#cn", "cn", "UTF-8", "en", false, (String[]) Arrays.asList(cn).toArray()));
            //eduOrgPostalAddress
            attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#eduOrgPostalAddress", "eduOrgPostalAddress", "UTF-8", "en", false, (String[]) Arrays.asList(univLocation).toArray()));

            Map< String, String> metadataProperties = new HashMap();
            AttributeSetStatus atrSetStatus = new AttributeSetStatus();
            atrSetStatus.setCode(AttributeSetStatus.CodeEnum.OK);

            List<String> matchingNames = matchingAttributes.stream().map(attr -> {
                return attr.getFriendlyName();
            }).collect(Collectors.toList());

            List<AttributeType> result = attributes.stream().filter(attr -> {
                return matchingNames.contains(attr.getFriendlyName());
            }).collect(Collectors.toList());

            //debug
            result.stream().forEach(att -> {
                Log.info("Will send to ACM attribute " + att.getFriendlyName() + att.getValues()[0]);
            });

            AttributeType[] attrArray = new AttributeType[result.size()];
            return new AttributeSet(id, TypeEnum.Response, issuer, recipient,
                    (AttributeType[]) result.toArray(attrArray), metadataProperties, smSessionId, "low", null, null, atrSetStatus);

        }
        return null;
    }

    public static AttributeSet buildFakeResponse(String issuer, String recipient, String smSessionId, List<AttributeType> matchingAttributes) throws JsonProcessingException {
        // ΠΕΤΡΟΥ PETROU
        // ΑΝΔΡΕΑΣ ANDREAS
        // 1980-01-01
        // GR/GR/ERMIS-11076669

        ObjectMapper mapper = new ObjectMapper();

        String id = UUID.randomUUID().toString();
        List<AttributeType> attributes = new ArrayList<>();
        String academicIdenitfier = "1234123131";
        String eduPersonAffiliation = "student";
        String eduPersonAffiliationGR = "student";
        String primaryAffiliation = "University of the Aegean";
        String primaryAffiliationGR = "Πανεπιστήμιου Αιγαίου";
        String email = "test@test.gr";
        String schacExpiryDate = "12/12/2020";
        String mobile = "0030694000000";
        String eduPersonPrincipalName = "Principal Name";
        String eduPersonPrincipalNamePrior = "Principal Name prior";
        String displayName = "Andreas Petrou";
        String sn = "PETROU";
        String givenName = "ANDREAS";
        String schacHomeOrganization = "aegean.gr";

        EidasCurrentAddress eidasAddress = new EidasCurrentAddress("locator", "throro", "postName", "postCode");
        EidasCurrentAddress[] addressValues = new EidasCurrentAddress[1];
        addressValues[0] = eidasAddress;
        String currentAddress = mapper.writeValueAsString(addressValues);

        attributes.add(new AttributeType("academicIdenitfier", "academicIdenitfier", "UTF-8", "en", false, (String[]) Arrays.asList(academicIdenitfier).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonAffiliation", "eduPersonAffiliation", "UTF-8", "en", false, (String[]) Arrays.asList(eduPersonAffiliation).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrimaryAffiliation", "eduPersonPrimaryAffiliation", "UTF-8", "en", false, (String[]) Arrays.asList(primaryAffiliation, primaryAffiliationGR).toArray()));
        attributes.add(new AttributeType("https://wiki.refeds.org/download/attachments/1606048/schac-20150413-1.5.0.schema.txt?version=1&modificationDate=1429044813839&api=v2#schacHomeOrganization", "schacHomeOrganization", "UTF-8", "en", false, (String[]) Arrays.asList(schacHomeOrganization).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#mail", "mail", "UTF-8", "en", false, (String[]) Arrays.asList(email).toArray()));
        attributes.add(new AttributeType("https://wiki.refeds.org/download/attachments/1606048/schac-20150413-1.5.0.schema.txt?version=1&modificationDate=1429044813839&api=v2#schacExpiryDate", "schacExpiryDate", "UTF-8", "en", false, (String[]) Arrays.asList(schacExpiryDate).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#mobile", "mobile", "UTF-8", "en", false, (String[]) Arrays.asList(mobile).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrincipalName", "eduPersonPrincipalName", "UTF-8", "en", false, (String[]) Arrays.asList(eduPersonPrincipalName).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrincipalNamePrior", "eduPersonPrincipalNamePrior", "UTF-8", "en", false, (String[]) Arrays.asList(eduPersonPrincipalNamePrior).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#displayName", "displayName", "UTF-8", "en", false, (String[]) Arrays.asList("displayName").toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#sn", "sn", "UTF-8", "en", false, (String[]) Arrays.asList(sn).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#givenName ", "givenName", "UTF-8", "en", false, (String[]) Arrays.asList(givenName).toArray()));

        attributes.add(new AttributeType("http://eidas.europa.eu/attributes/naturalperson/BirthName", "BirthName", "UTF-8", "en", false, (String[]) Arrays.asList("birthname").toArray()));
        attributes.add(new AttributeType("http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth", "PlaceOfBirth", "UTF-8", "en", false, (String[]) Arrays.asList("PlaceOfBirth").toArray()));
        attributes.add(new AttributeType("http://eidas.europa.eu/attributes/naturalperson/CurrentAddress", "CurrentAddress", "UTF-8", "en", false, (String[]) Arrays.asList(currentAddress).toArray()));
        attributes.add(new AttributeType("http://eidas.europa.eu/attributes/naturalperson/Gender", "Gender", "UTF-8", "en", false, (String[]) Arrays.asList("M").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#cn", "cn", "UTF-8", "en", false, (String[]) Arrays.asList("cn").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#eduOrgHomePageURI", "eduOrgHomePageURI", "UTF-8", "en", false, (String[]) Arrays.asList("eduOrgHomePageURI").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#eduOrgLegalName", "eduOrgLegalName", "UTF-8", "en", false, (String[]) Arrays.asList("eduOrgLegalName").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#eduOrgPostalAddress", "eduOrgPostalAddress", "UTF-8", "en", false, (String[]) Arrays.asList("eduOrgPostalAddress").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#l", "l", "UTF-8", "en", false, (String[]) Arrays.asList("l").toArray()));

        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrimaryOrgUnitDN", "eduPersonOrgUnitDN", "UTF-8", "en", false, (String[]) Arrays.asList("eduPersonOrgUnitDN").toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonUniqueId", "eduPersonUniqueId", "UTF-8", "en", false, (String[]) Arrays.asList("eduPersonUniqueId").toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#o", "o", "UTF-8", "en", false, (String[]) Arrays.asList("o").toArray()));

        Map< String, String> metadataProperties = new HashMap();
        AttributeSetStatus atrSetStatus = new AttributeSetStatus();
        atrSetStatus.setCode(AttributeSetStatus.CodeEnum.OK);

        List<String> matchingNames = matchingAttributes.stream().map(attr -> {
            return attr.getFriendlyName();
        }).collect(Collectors.toList());

        List<AttributeType> result = attributes.stream().filter(attr -> {
            return matchingNames.contains(attr.getFriendlyName());
        }).collect(Collectors.toList());

        AttributeType[] attrArray = new AttributeType[result.size()];
        return new AttributeSet(id, TypeEnum.Response, issuer, recipient,
                (AttributeType[]) result.toArray(attrArray), metadataProperties, smSessionId, "low", null, null, atrSetStatus);

    }

    public static AttributeSet buildFakeItalianResponse(String issuer, String recipient, String smSessionId, List<AttributeType> matchingAttributes) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();

        String id = UUID.randomUUID().toString();
        List<AttributeType> attributes = new ArrayList<>();
        String academicIdenitfier = "1234123131";
        String eduPersonAffiliation = "student";
        String primaryAffiliation = "University of the Aegean";
        String primaryAffiliationGR = "Πανεπιστήμιου Αιγαίου";
        String email = "Mario@aegean.gr";
        String schacExpiryDate = "12/12/2020";
        String mobile = "0030694000000";
        String eduPersonPrincipalName = "marioFerdinando@aegean.gr";
        String eduPersonPrincipalNamePrior = "marioFerdinando@aegean.gr";
        String sn = "Ferdinando Faiella";
        String givenName = "Mario";
        String schacHomeOrganization = "aegean.gr";

        EidasCurrentAddress eidasAddress = new EidasCurrentAddress("locator", "throro", "postName", "postCode");
        EidasCurrentAddress[] addressValues = new EidasCurrentAddress[1];
        addressValues[0] = eidasAddress;
        String currentAddress = mapper.writeValueAsString(addressValues);

        attributes.add(new AttributeType("academicIdenitfier", "academicIdenitfier", "UTF-8", "en", false, (String[]) Arrays.asList(academicIdenitfier).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonAffiliation", "eduPersonAffiliation", "UTF-8", "en", false, (String[]) Arrays.asList(eduPersonAffiliation).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrimaryAffiliation", "eduPersonPrimaryAffiliation", "UTF-8", "en", false, (String[]) Arrays.asList(primaryAffiliation, primaryAffiliationGR).toArray()));
        attributes.add(new AttributeType("https://wiki.refeds.org/download/attachments/1606048/schac-20150413-1.5.0.schema.txt?version=1&modificationDate=1429044813839&api=v2#schacHomeOrganization", "schacHomeOrganization", "UTF-8", "en", false, (String[]) Arrays.asList(schacHomeOrganization).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#mail", "mail", "UTF-8", "en", false, (String[]) Arrays.asList(email).toArray()));
        attributes.add(new AttributeType("https://wiki.refeds.org/download/attachments/1606048/schac-20150413-1.5.0.schema.txt?version=1&modificationDate=1429044813839&api=v2#schacExpiryDate", "schacExpiryDate", "UTF-8", "en", false, (String[]) Arrays.asList(schacExpiryDate).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#mobile", "mobile", "UTF-8", "en", false, (String[]) Arrays.asList(mobile).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrincipalName", "eduPersonPrincipalName", "UTF-8", "en", false, (String[]) Arrays.asList(eduPersonPrincipalName).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrincipalNamePrior", "eduPersonPrincipalNamePrior", "UTF-8", "en", false, (String[]) Arrays.asList(eduPersonPrincipalNamePrior).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#displayName", "displayName", "UTF-8", "en", false, (String[]) Arrays.asList("displayName").toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#sn", "sn", "UTF-8", "en", false, (String[]) Arrays.asList(sn).toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#givenName ", "givenName", "UTF-8", "en", false, (String[]) Arrays.asList(givenName).toArray()));

        attributes.add(new AttributeType("http://eidas.europa.eu/attributes/naturalperson/BirthName", "BirthName", "UTF-8", "en", false, (String[]) Arrays.asList("birthname").toArray()));
        attributes.add(new AttributeType("http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth", "PlaceOfBirth", "UTF-8", "en", false, (String[]) Arrays.asList("PlaceOfBirth").toArray()));
        attributes.add(new AttributeType("http://eidas.europa.eu/attributes/naturalperson/CurrentAddress", "CurrentAddress", "UTF-8", "en", false, (String[]) Arrays.asList(currentAddress).toArray()));
        attributes.add(new AttributeType("http://eidas.europa.eu/attributes/naturalperson/Gender", "Gender", "UTF-8", "en", false, (String[]) Arrays.asList("M").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#cn", "cn", "UTF-8", "en", false, (String[]) Arrays.asList("cn").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#eduOrgHomePageURI", "eduOrgHomePageURI", "UTF-8", "en", false, (String[]) Arrays.asList("http://aegean.gr").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#eduOrgLegalName", "eduOrgLegalName", "UTF-8", "en", false, (String[]) Arrays.asList("University of the Aegean").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#eduOrgPostalAddress", "eduOrgPostalAddress", "UTF-8", "en", false, (String[]) Arrays.asList("Mytilini Greece").toArray()));
        attributes.add(new AttributeType("https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduOrg-200210.pdf#l", "l", "UTF-8", "en", false, (String[]) Arrays.asList("l").toArray()));

        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonPrimaryOrgUnitDN", "eduPersonOrgUnitDN", "UTF-8", "en", false, (String[]) Arrays.asList("ou=Faculty of sciences,o=University of the Aegean,c=GR ou=CS,o=UAegean,dc=aegean,dc=gr").toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonUniqueId", "eduPersonUniqueId", "UTF-8", "en", false, (String[]) Arrays.asList("123456").toArray()));
        attributes.add(new AttributeType("https://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#o", "UAegean", "UTF-8", "en", false, (String[]) Arrays.asList("o").toArray()));

        Map< String, String> metadataProperties = new HashMap();
        AttributeSetStatus atrSetStatus = new AttributeSetStatus();
        atrSetStatus.setCode(AttributeSetStatus.CodeEnum.OK);

        List<String> matchingNames = matchingAttributes.stream().map(attr -> {
            return attr.getFriendlyName();
        }).collect(Collectors.toList());

        List<AttributeType> result = attributes.stream().filter(attr -> {
            return matchingNames.contains(attr.getFriendlyName());
        }).collect(Collectors.toList());

        AttributeType[] attrArray = new AttributeType[result.size()];
        return new AttributeSet(id, TypeEnum.Response, issuer, recipient,
                (AttributeType[]) result.toArray(attrArray), metadataProperties, smSessionId, "low", null, null, atrSetStatus);

    }

}
