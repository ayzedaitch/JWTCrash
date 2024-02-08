package com.springsecurity.JWTCrash.controllers;

import com.springsecurity.JWTCrash.dto.LoginResponseDTO;
import com.springsecurity.JWTCrash.dto.RegistrationDTO;
import com.springsecurity.JWTCrash.models.ApplicationUser;
import com.springsecurity.JWTCrash.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthenticationController {

    @Autowired
    AuthenticationService authenticationService;



    @PostMapping("/register")
    public ApplicationUser registerUser(@RequestBody RegistrationDTO body){
        return authenticationService.registerUser(body.getUsername(), body.getPassword());
    }

    @PostMapping("/login")
    public LoginResponseDTO loginUser(@RequestBody RegistrationDTO body){
        return authenticationService.loginUser(body.getUsername(), body.getPassword());
    }

}
