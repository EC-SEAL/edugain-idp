/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLRelayStateSuccessHandler;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 *
 * @author nikos
 */
@Configuration
public class SamlSecurityConfig extends WebSecurityConfigurerAdapter {

    private final static Logger log = LoggerFactory.getLogger(SamlSecurityConfig.class);

    //docker run -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin -p 8081:8080 jboss/keycloak
    // do not forget to add the keycloak saml client
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //configuring HttpSecurity to declare which AuthenticationEntryPoint to call when an authentication exception is triggered
        //redirect to samlEntryPoint if unauthenticated
        http
                .exceptionHandling()
                .authenticationEntryPoint(samlEntryPoint());

        //Disable csrf
        http
                .csrf()
                .disable();
        //Add the saml filter chain that has been built so far
        http
                .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
        //Permit certain URL patterns (/error, /saml/**)
        http
                .authorizeRequests()
                .antMatchers("/error").permitAll()
                .antMatchers("/grap/error").permitAll()
                .antMatchers("/grap/authfail").permitAll()
                .antMatchers("/authfail").permitAll()
                .antMatchers("/css").permitAll()
                .antMatchers("/img").permitAll()
                .antMatchers("/js").permitAll()
                .antMatchers("/resources/**").permitAll()
                .antMatchers("/css/**", "/js/**", "/images/**", "/img/**").permitAll()
                .antMatchers("/grap/css/**", "/grap/js/**", "/grap/images/**", "/grap/img/**").permitAll()
                .antMatchers("/saml/**").permitAll()
                .antMatchers("/grap/saml/**").permitAll()
                .antMatchers("/ap/forward").permitAll()
                .antMatchers("/grap/ap/forward").permitAll()
                .antMatchers("/ap/query").permitAll()
                .antMatchers("/grap/ap/query").permitAll()
                .antMatchers("/ap/proceedAfterError").permitAll()
                .antMatchers("/grap/ap/proceedAfterError").permitAll()
                .anyRequest().authenticated();

        // handle logout
        http
                .logout()
                .logoutSuccessUrl("/");

    }

    /*
    *Users will try to access a SAML protected resource and fail.
    This failure will be handled by Spring security ExceptionTranslationFilter
    implementation which then will hand over to saml authentication entry point thus starting
    the saml authentication from your app (Service Provider or SP) to the identity provider (IdP).
     */
    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();

        webSSOProfileOptions.setRelayState("https://mywebsite"); // ????
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SamlWithRelayStateEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        samlEntryPoint.setFilterProcessesUrl("/saml/login");
        return samlEntryPoint;
    }

    /*
    This metadata will be provided/uploaded to the IDP.
     */
    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler();
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SAMLRelayStateSuccessHandler();
//        successRedirectHandler.setTargetUrlParameter("session");

        successRedirectHandler.setDefaultTargetUrl("/as/samlSuccess");

        return successRedirectHandler;
    }

    /*
    After user logs in, the IDP redirects the SAML response to a configured URL (e.g. «/saml/SSO»)
    This redirection triggers the following filter bean class: SamlWebSSOProcessingFilter
     */
    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        System.out.println(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOProcessingFilter;
    }

    //Global logout can be configured with these beans
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler simpleUrlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        simpleUrlLogoutSuccessHandler.setDefaultTargetUrl("/");
        simpleUrlLogoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        return simpleUrlLogoutSuccessHandler;
    }

    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler
                = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[]{logoutHandler()},
                new LogoutHandler[]{logoutHandler()});
    }

    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(),
                logoutHandler());
    }

    //SP Metadata generation
    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }

    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
//        metadataGenerator.setEntityId("APP_ENTITY_ID"); // esmoSamlClient
        metadataGenerator.setEntityId("esmoSamlClient"); //
//        metadataGenerator.setEntityBaseURL("APP_BASE_URL");
//        metadataGenerator.setEntityBaseURL("localhost:8080");
//System.getenv(paramName)
        metadataGenerator.setEntityBaseURL(System.getenv("APP_BASE_URL"));
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        return metadataGenerator;
    }

    // keys store for saml keys
    @Bean
    public KeyManager keyManager() {
        ClassPathResource storeFile = new ClassPathResource("/saml2-keystore.jks");
        String storePass = "mystorepass";
        Map<String, String> passwords = new HashMap<>();
        passwords.put("myapp", "mykeypass");
        return new JKSKeyManager(storeFile, storePass, passwords, "myapp");
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        extendedMetadata.setSignMetadata(false);
        return extendedMetadata;
    }

    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        //add the metadata to the filter chain
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"), metadataDisplayFilter()));
        // add the protected resource to the filter chain
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));
        // add the auth response filter
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()));

        //add logout filters
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter()));

        return new FilterChainProxy(chains);
    }

    //XML parsing to read the metadata of teh idp
    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }

    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    //SAML Binding configurLation, depends on the IDP specifications
    @Bean
    public HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), velocityEngine());
    }

    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool());
    }

    @Bean
    public SAMLProcessorImpl processor() {
        Collection<SAMLBinding> bindings = new ArrayList<>();
        bindings.add(httpRedirectDeflateBinding());
        bindings.add(httpPostBinding());
        return new SAMLProcessorImpl(bindings);
    }

    // initialize HTTPClient with multithreaded connection manager,
    @Bean
    public HttpClient httpClient() {
        return new HttpClient(multiThreadedHttpConnectionManager());
    }

    @Bean
    public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }

    //    //SAML BootStrap which is responsible for the initialization of SAML library and is automatically called as part of Spring initialization
    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
//        return new SAMLBootstrap(); // the default impl uses sha-1 which is now considered insecure
        return new SAMLBootstrap();
    }

    //initialize saml logger
    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }
//
//    //SAMLContextProviderImpl is responsible for parsing HttpRequest/Response and determining which local entity (IDP/SP) is responsible for its handling.
//    @Bean
//    public SAMLContextProviderImpl contextProvider() {
//        return new SAMLContextProviderImpl();
//    }

    //Web SSO profile
    // SAML 2.0 WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }

    // SAML 2.0 Web SSO profile
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    // not used but autowired...
    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // not used but autowired...
    // SAML 2.0 Holder-of-Key Web SSO profile
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }

    //IdP metadata
    //ONELOGIN_METADATA_URL.concat(getAppId()) –The IDPs metadata URL followed by the unique app Id for the application set in the IDP
    @Bean
    public ExtendedMetadataDelegate idpMetadata()
            throws MetadataProviderException, ResourceException {

        Timer backgroundTaskTimer = new Timer(true);
//        HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(backgroundTaskTimer, new HttpClient(), "http://localhost:8081/auth/realms/master/protocol/saml/descriptor");
        HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(backgroundTaskTimer, new HttpClient(), "http://idp.oktadev.com/metadata");
        httpMetadataProvider.setParserPool(parserPool());

        ExtendedMetadataDelegate extendedMetadataDelegate
                = new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(true);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        return extendedMetadataDelegate;
    }

    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException, ResourceException {
        List<MetadataProvider> providers = new ArrayList<>();
        providers.add(idpMetadata());
        return new CachingMetadataManager(providers);
    }
//
//    //Spring security
//    // AuthenticationProvider
//    // The authentication provider is capable of verifying the validity of a SAMLAuthenticationToken
//    // and in case the token is valid to create an authenticated UsernamePasswordAuthenticationToken

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//                .authenticationProvider(samlAuthenticationProvider());
//    }

    @Bean
    public SAMLContextProviderImpl contextProvider() {

        log.info("Using SAMLContextProviderLB implementation of SAMLContextProvider for context provider bean.");
        final SAMLContextProviderLB lb = new SAMLContextProviderLB();

        log.info("Setting the load balancer scheme to {}", "https");
        lb.setScheme("http");

        log.info("Setting the load balancer server name to {}", "serverName");
        lb.setServerName("localhost:8080");

        log.info("Setting the load balancer context path to {}", "/grap");
        lb.setContextPath("");

        log.info("Setting the load balancer port to {}", 80);
        lb.setServerPort(80);

        log.info("Setting whether to include the server port in the request URL to {}", false);
        lb.setIncludeServerPortInRequestURL(false);
        return lb;

    }

}
