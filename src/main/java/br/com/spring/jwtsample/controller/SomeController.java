package br.com.spring.jwtsample.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api")
public class SomeController {

    @GetMapping("/public")
    public @ResponseBody String getPublicMessage() {
        return "I am public!";
    }

    @GetMapping("/private")
    public @ResponseBody String getPrivateMessage() {
        return "I am private!";
    }

    @GetMapping("/private/admin")
    public @ResponseBody String getPrivateAdminMessage() {
        return "I am private Admin!";
    }
    
}