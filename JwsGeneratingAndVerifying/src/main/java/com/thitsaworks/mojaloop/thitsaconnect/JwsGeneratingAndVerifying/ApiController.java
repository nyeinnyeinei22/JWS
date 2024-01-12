package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class ApiController {

    private static final Logger LOG = LoggerFactory.getLogger(ApiController.class);
    @Autowired
    private JwtUtil jwtUtil;

    @RequestMapping(value = "/api/login", method = RequestMethod.POST)
    public ResponseEntity<String> login(@Valid @RequestParam(required = false) String user_name) {
        String token = jwtUtil.generateToken(user_name);
        return ResponseEntity.ok(token);
    }

    @RequestMapping(value = "/api/user", method = RequestMethod.GET)
    public ResponseEntity<String> getUser(@RequestHeader("Authorization") String authorizationHeader) {
        String token = authorizationHeader.substring("Bearer ".length());
        String username = jwtUtil.validateToken(token);
        return ResponseEntity.ok(username);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
    }

}
