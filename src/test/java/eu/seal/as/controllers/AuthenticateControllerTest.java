package eu.seal.as.controllers;

import eu.seal.as.CommonTestSupport;
import eu.seal.as.service.EsmoMetadataService;
import eu.seal.as.service.KeyStoreService;
import eu.seal.as.service.NetworkService;
import eu.seal.as.service.ParameterService;
import net.spy.memcached.compat.log.LoggerFactory;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.View;

import com.google.api.client.http.HttpResponse;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ConsoleAppender;

import static org.junit.Assert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@TestPropertySource(properties = {"SESSION_MANAGER_URL = http://127.0.0.1:8000"})
public class AuthenticateControllerTest extends BaseTest {
	
    @InjectMocks
    private ASControllers asControllers;

    @Mock
    private View mockView;
    @Mock
    private ParameterService paramServ;
    @Mock
    private KeyStoreService keyServ;
    @Mock
    private EsmoMetadataService metadataServ;

    private MockMvc mockMvc;
    

    @Before
    public void setUp() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, IOException
    {	
        MockitoAnnotations.initMocks(this);     
        asControllers = new ASControllers(paramServ, keyServ, metadataServ);
        mockMvc = standaloneSetup(asControllers)
                .setCustomArgumentResolvers(new MockArgumentResolver())
                .setSingleView(mockView).build();
    }
    
//    @Test
//    public void testAuthentication() throws Exception {
//        mockMvc.perform(get("/as/authenticate"))
//                .andExpect(status().isOk());
//    }
//    
    @Test
    public void testCallBack() throws Exception {
        mockMvc.perform(post("/as/samlSuccess"))
                .andExpect(status().isOk());
    }
    
    private static class MockArgumentResolver implements HandlerMethodArgumentResolver
    {
        @Override
        public boolean supportsParameter(MethodParameter methodParameter) {
            return methodParameter.getParameterType().equals(User.class);
        }

        @Override
        public Object resolveArgument(MethodParameter methodParameter,
                                      ModelAndViewContainer modelAndViewContainer,
                                      NativeWebRequest nativeWebRequest,
                                      WebDataBinderFactory webDataBinderFactory)
                                    		  throws Exception {
            return CommonTestSupport.USER_DETAILS;
        }
    }

}
