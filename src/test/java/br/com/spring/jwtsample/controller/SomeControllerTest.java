package br.com.spring.jwtsample.controller;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;


@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@Import(br.com.spring.jwtsample.security.SecurityConfig.class)
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
    

    
}