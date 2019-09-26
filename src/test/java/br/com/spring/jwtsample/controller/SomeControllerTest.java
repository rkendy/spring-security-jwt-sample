package br.com.spring.jwtsample.controller;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import br.com.spring.jwtsample.security.JwtConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;


@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@Import(br.com.spring.jwtsample.security.SecurityConfig.class)      // Habilita configuracao de seguranca
public class SomeControllerTest {

    @Autowired
    private SomeController controller;

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testControllerNotNull() {
        assertNotNull(controller);
    }

    @Test
    public void shouldReturn200() throws Exception {
        this.mockMvc.perform(MockMvcRequestBuilders.get("/api/public"))
            .andDo(MockMvcResultHandlers.print())
            .andExpect(MockMvcResultMatchers.status().isOk());
    }


    @Test
    public void shouldReturn403() throws Exception {
        this.mockMvc.perform(MockMvcRequestBuilders.get("/api/private"))
            .andDo(MockMvcResultHandlers.print())
            .andExpect(MockMvcResultMatchers.status().isForbidden());
    }


    private ResultActions login(String username, String password) throws Exception {
        return mockMvc.perform(MockMvcRequestBuilders
            .post("/login")
            .param("username", username)
            .param("password", password));
    }

    private String loginAndReturnToken(String user, String password) throws Exception {
        ResultActions result = login(user, password);            
        String headerStr = result.andReturn().getResponse().getHeader(JwtConstants.HEADER);
        return headerStr.substring(JwtConstants.PREFIX.length());
    }

    @Test
    public void shouldLoginOk() throws Exception {
        login("username", "password").andExpect(MockMvcResultMatchers.status().isOk());        
    }

    @Test
    public void shouldLoginAndReturnValidToken() throws Exception {
        String token = loginAndReturnToken("user", "password");
        byte[] signinkey = JwtConstants.SECRET.getBytes();
        Jws<Claims> parsedToken = Jwts.parser()
                                    .setSigningKey(signinkey)
                                    .parseClaimsJws(token.replace(JwtConstants.HEADER, ""));
        String username = parsedToken.getBody().getSubject();
        Date date = parsedToken.getBody().getExpiration();

        assertEquals("user", username);
        LocalDateTime afterExpiration = LocalDateTime.now();
        afterExpiration = afterExpiration.plus(JwtConstants.EXPIRATION + 1000, ChronoUnit.MILLIS);
        Date afterExpirationDate = Date.from(afterExpiration.atZone(ZoneId.systemDefault()).toInstant());
        assertTrue(date.before(afterExpirationDate));
    }

    @Test
    public void shouldLoginAndAccessWithoutAdminRole() throws Exception {
        String token = loginAndReturnToken("user", "password");
        mockMvc.perform(MockMvcRequestBuilders.get("/api/private")
                            .header(JwtConstants.HEADER, JwtConstants.PREFIX + token))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    @Test
    public void shouldLoginAndNotAccessWithoutAdminRole() throws Exception {
        String token = loginAndReturnToken("user", "password");
        mockMvc.perform(MockMvcRequestBuilders.get("/api/private/admin")
                            .header(JwtConstants.HEADER, JwtConstants.PREFIX + token))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }
    
    @Test
    public void shouldLoginAndAccessWithAdminRole() throws Exception {
        String token = loginAndReturnToken("admin", "password");
        mockMvc.perform(MockMvcRequestBuilders.get("/api/private/admin")
                            .header(JwtConstants.HEADER, JwtConstants.PREFIX + token))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }
    

    
}