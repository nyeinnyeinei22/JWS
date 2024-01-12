package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

@RestController
public class GetSignatureContoller {

    private static final Logger LOG = LoggerFactory.getLogger(GetSignatureContoller.class);

    @Autowired
    private GetSignature getSignature;

    @RequestMapping(value = "/api/signature", method = RequestMethod.POST)
    public ResponseEntity<String> signature(@Valid @RequestParam(required = false) String alg,
                                            String fspiop_uri,
                                            String fspiop_source,
                                            String fspiop_destination,
                                            String date,
                                            @RequestBody SignatureRequest body) throws Exception {

        Map<String, String> protectedHeaderObject = new HashMap<>();
        protectedHeaderObject.put("alg", alg);
        protectedHeaderObject.put("FSPIOP-URI", fspiop_uri);
        protectedHeaderObject.put("uri", fspiop_uri);
        protectedHeaderObject.put("FSPIOP-HTTP-Method", RequestMethod.POST.toString());
        protectedHeaderObject.put("FSPIOP-Source", fspiop_source);

        // set destination in the protected header object if it is present in the request headers
        if (fspiop_destination != null) {
            protectedHeaderObject.put("FSPIOP-Destination", fspiop_destination);
        }

        // set date in the protected header object if it is present in the request headers
        if (date != null) {
            protectedHeaderObject.put("Date", date);
        }

        if (body != null) {
            protectedHeaderObject.put("body", body.getBody().toString());
        }

        String token = getSignature.getSignature(protectedHeaderObject);
        return ResponseEntity.ok(token);
    }

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class SignatureRequest implements Serializable {

        @NotNull
        @JsonProperty("body")
        private Object body;

    }
}
