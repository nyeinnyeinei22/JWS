package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.Base64;

import com.nimbusds.jose.shaded.gson.Gson;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;

/**
 * Provides methods for Mojaloop compliant JWS signing and signature verification
 */
public class JwsValidator {
    private Logger logger;
    private Map<String, String> validationKeys;
    private static final String SIGNATURE_ALGORITHM = "RS256";

    public JwsValidator(Map<String, String> validationKeys) {
        this.logger = Logger.getLogger(JwsValidator.class.getName());
        if(validationKeys == null) {
            throw new IllegalArgumentException("Validation keys must be supplied as config argument");
        }
        this.validationKeys = validationKeys;
    }

    /**
     * Validates the JWS headers on an incoming HTTP request
     * Throws if the protected header or signature are not valid
     */
    public void validate(Map<String, String> headers, String body, String data) {
        try {
            String payload = body != null ? body : data;
            logger.log(Level.INFO, "Validing JWS on request with headers: {0} and body: {1}", new Object[]{headers, payload});
            if(payload == null) {
                throw new IllegalArgumentException("Cannot validate JWS without a body");
            }
            // first check we have a public (validation) key for the request source
            if(!headers.containsKey("fspiop-source")) {
                throw new IllegalArgumentException("FSPIOP-Source HTTP header not in request headers. Unable to verify JWS");
            }
            String pubKey = this.validationKeys.get(headers.get("fspiop-source"));
            if(pubKey == null) {
                throw new IllegalArgumentException("JWS public key for '" + headers.get("fspiop-source") + "' not available. Unable to verify JWS. Only have keys for: " + this.validationKeys.keySet());
            }
            // first we check the required headers are present
            if(!headers.containsKey("fspiop-uri") || !headers.containsKey("fspiop-http-method") || !headers.containsKey("fspiop-signature")) {
                throw new IllegalArgumentException("fspiop-uri, fspiop-http-method and fspiop-signature HTTP headers are all required for JWS. Only got " + headers);
            }
            // if all required headers are present we start by extracting the components of the signature header
            String signatureHeader = headers.get("fspiop-signature");
            Map<String, Object> signatureHeaderMap = new HashMap<>();
            signatureHeaderMap = (Map<String, Object>) new Gson().fromJson(signatureHeader, signatureHeaderMap.getClass());
            String protectedHeader = (String) signatureHeaderMap.get("protectedHeader");
            String signature = (String) signatureHeaderMap.get("signature");
            String token = protectedHeader + "." + Base64.getEncoder().encodeToString(payload.getBytes()) + "." + signature;
            // validate signature
            Claims result = Jwts.parser()
                                .setSigningKey(pubKey)
                                .require(SIGNATURE_ALGORITHM, true)
                                .parseClaimsJws(token)
                                .getBody();
            // check protected header has all required fields and matches actual incoming headers
            this._validateProtectedHeader(headers, result);
            logger.log(Level.INFO, "JWS verify result: {0}", result);
            // all ok if we got here
          //  logger.log(Level.INFO, "JWS valid for request {0}", request);
        }
        catch(Exception e) {
            logger.log(Level.SEVERE, "Error validating JWS: {0}", e.getMessage());
            throw e;
        }
    }

    /**
     * Validates the protected header and checks it against the actual request headers.
     * Throws an exception if a discrepancy is detected or validation fails.
     */
    private void _validateProtectedHeader(Map<String, String> headers, Claims decodedProtectedHeader) {
        // check alg is present and is the single permitted value
        if(!decodedProtectedHeader.containsKey("alg")) {
            throw new IllegalArgumentException("Decoded protected header does not contain required alg element: " + decodedProtectedHeader);
        }
        if(!decodedProtectedHeader.get("alg").equals(SIGNATURE_ALGORITHM)) {
            throw new IllegalArgumentException("Invalid protected header alg '" + decodedProtectedHeader.get("alg") + "' should be '" + SIGNATURE_ALGORITHM + "'");
        }
        // check FSPIOP-URI is present and matches
        if(!decodedProtectedHeader.containsKey("FSPIOP-URI")) {
            throw new IllegalArgumentException("Decoded protected header does not contain required FSPIOP-URI element: " + decodedProtectedHeader);
        }
        if(!headers.containsKey("fspiop-uri")) {
            throw new IllegalArgumentException("FSPIOP-URI HTTP header not present in request headers: " + headers);
        }
        if(!decodedProtectedHeader.get("FSPIOP-URI").equals(headers.get("fspiop-uri"))) {
            throw new IllegalArgumentException("FSPIOP-URI HTTP request header value: " + headers.get("fspiop-uri") + " does not match protected header value: " + decodedProtectedHeader.get("FSPIOP-URI"));
        }
        // check FSPIOP-HTTP-Method is present and matches
        if(!decodedProtectedHeader.containsKey("FSPIOP-HTTP-Method")) {
            throw new IllegalArgumentException("Decoded protected header does not contain required FSPIOP-HTTP-Method element: " + decodedProtectedHeader);
        }
        if(!headers.containsKey("fspiop-http-method")) {
            throw new IllegalArgumentException("FSPIOP-HTTP-Method HTTP header not present in request headers: " + headers);
        }
        if(!decodedProtectedHeader.get("FSPIOP-HTTP-Method").equals(headers.get("fspiop-http-method"))) {
            throw new IllegalArgumentException("FSPIOP-HTTP-Method HTTP request header value: " + headers.get("fspiop-http-method") + " does not match protected header value: " + decodedProtectedHeader.get("FSPIOP-HTTP-Method"));
        }
        // check FSPIOP-Source is present and matches
        if(!decodedProtectedHeader.containsKey("FSPIOP-Source")) {
            throw new IllegalArgumentException("Decoded protected header does not contain required FSPIOP-Source element: " + decodedProtectedHeader);
        }
        if(!headers.containsKey("fspiop-source")) {
            throw new IllegalArgumentException("FSPIOP-Source HTTP header not present in request headers: " + headers);
        }
        if(!decodedProtectedHeader.get("FSPIOP-Source").equals(headers.get("fspiop-source"))) {
            throw new IllegalArgumentException("FSPIOP-Source HTTP request header value: " + headers.get("fspiop-source") + " does not match protected header value: " + decodedProtectedHeader.get("FSPIOP-Source"));
        }
        // if we have a Date field in the protected header it must be present in the HTTP header and the values should match exactly
        if(decodedProtectedHeader.containsKey("Date") && !headers.containsKey("date")) {
            throw new IllegalArgumentException("Date header is present in protected header but not in HTTP request: " + headers);
        }
        if(decodedProtectedHeader.containsKey("Date") && !headers.get("date").equals(decodedProtectedHeader.get("Date"))) {
            throw new IllegalArgumentException("HTTP date header: " + headers.get("date") + " does not match protected header Date value: " + decodedProtectedHeader.get("Date"));
        }
        // if we have an HTTP fspiop-destination header it should also be in the protected header and the values should match exactly
        if(headers.containsKey("fspiop-destination") && !decodedProtectedHeader.containsKey("FSPIOP-Destination")) {
            throw new IllegalArgumentException("HTTP fspiop-destination header is present but is not present in protected header: " + decodedProtectedHeader);
        }
        if(decodedProtectedHeader.containsKey("FSPIOP-Destination") && !headers.containsKey("fspiop-destination")) {
            throw new IllegalArgumentException("FSPIOP-Destination header is present in protected header but not in HTTP request: " + headers);
        }
        if(headers.containsKey("fspiop-destination") && !headers.get("fspiop-destination").equals(decodedProtectedHeader.get("FSPIOP-Destination"))) {
            throw new IllegalArgumentException("HTTP FSPIOP-Destination header: " + headers.get("fspiop-destination") + " does not match protected header FSPIOP-Destination value: " + decodedProtectedHeader.get("FSPIOP-Destination"));
        }
    }
}


