export ASYNC_SIGNATURE=true
export KEY_PASS=selfsignedpass
export STORE_PASS=keystorepass
export SIGNING_SECRET=selfsigned
export JWT_CERT_ALIAS=selfsigned
export HTTPSIG_CERT_ALIAS=1
export ESMO_SERVICE_DESCRIPTION=UAegean Identity Provider
export ESMO_DEFAULT_NAME=UAegean Attribute Provider
export ESMO_SUPPORTED_ENC_ALGORITHMS=RSA-SHA256
export SESSION_MANAGER_URL=http://vm.project-seal.eu:9090
export KEYSTORE_PATH=resources/testKeys/keystore.jks
export SUPPORTED_CLAIMS=eduPersonAffiliation,primaryAffiliation,schacHomeOrganization,mail,schacExpiryDate,mobile,eduPersonPrincipalName,eduPersonPrincipalNamePrior,displayName,sn,givenName,eduOrgLegalName,cn,eduOrgPostalAddress,eduOrgHomePageURI
export IDP_METADATA_URL=http://localhost:8081/auth/realms/master/protocol/saml/descriptor
export KEYSTORE_PASS=nalle123
export KEYSTORE_ID=apollo
export TESTING=true

