package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class JwsValidatorController {

    private static final Logger LOG = LoggerFactory.getLogger(JwsValidatorController.class);

    @Autowired
    private JwsValidatorOld jwsValidatorOld;

    @RequestMapping(value = "/api/validator", method = RequestMethod.POST)
    public ResponseEntity<String> validator(@Valid @RequestParam(required = false) String signature
    ) throws Exception {

        boolean validate = (signature.isBlank() || signature.isEmpty()) ? false : jwsValidatorOld.validate(signature);
        return ResponseEntity.ok(validate ? "Valid Signature" : "Invalid Signature");
    }

}
