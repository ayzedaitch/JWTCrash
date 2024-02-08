package com.springsecurity.JWTCrash.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyGeneratorUtility {

    public static KeyPair generateRsaKey(){

        KeyPair keyPair;
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // 2048 bits
            keyPair = keyPairGenerator.generateKeyPair();

        } catch (Exception e){
            throw new IllegalStateException();
        }
        return keyPair;
    }
}
