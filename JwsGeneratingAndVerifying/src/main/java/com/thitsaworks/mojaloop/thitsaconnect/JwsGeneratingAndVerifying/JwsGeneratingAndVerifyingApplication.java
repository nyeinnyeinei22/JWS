package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
public class JwsGeneratingAndVerifyingApplication {

    public static void main(String[] args) {

        SpringApplication.run(JwsGeneratingAndVerifyingApplication.class, args);

    }
}
