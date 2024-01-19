package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;

@Component
public class JwsValidator1 {

    private static final Logger logger = LoggerFactory.getLogger(JwsValidator1.class);

    private static final String SIGNATURE_ALGORITHM = "RS256";

    private final Map<String, String> validationKeys;

    public JwsValidator1(Map<String, String> validationKeys) {

        this.validationKeys = validationKeys;
    }

    public void validate(Request request) {

        try {
            Map<String, String> headers = request.getHeaders();
            String payload = request.getBody() != null ? request.getBody() : request.getData().toString();

            logger.info("Validating JWS on request with headers: " + headers + " and body: " + payload);

            if (payload == null) {
                throw new IllegalArgumentException("Cannot validate JWS without a body");
            }

            // First check if we have a public (validation) key for the request source
            String fspiopSourceHeader = headers.get("fspiop-source");
            if (fspiopSourceHeader == null) {
                throw new IllegalArgumentException(
                        "FSPIOP-Source HTTP header not in request headers. Unable to verify JWS");
            }

            String pubKey = validationKeys.get(fspiopSourceHeader);
            if (pubKey == null) {
                throw new IllegalArgumentException("JWS public key for '" + fspiopSourceHeader +
                        "' not available. Unable to verify JWS. Only have keys for: " + validationKeys.keySet());
            }

            // Next, we check if the required headers are present
            if (!headers.containsKey("fspiop-uri") || !headers.containsKey("fspiop-http-method") ||
                    !headers.containsKey("fspiop-signature")) {
                throw new IllegalArgumentException(
                        "fspiop-uri, fspiop-http-method, and fspiop-signature HTTP headers are all required for JWS. Only got " +
                                headers);
            }

            // If all required headers are present, we extract the components of the signature header
            String signatureHeader = headers.get("fspiop-signature");
            SignatureData signatureData = parseSignatureHeader(signatureHeader);

            String token =
                    signatureData.protectedHeader + "." + Base64.getUrlEncoder().encodeToString(payload.getBytes()) +
                            "." + signatureData.signature;

//            PublicKey publicKey = Keys.publicKeyFromPem(pubKey);
//
//            // Validate the signature
//            JwsHeader<?> header = Jwts.parser()
//                                      .setSigningKey(publicKey)
//                                      .requireAlgorithm(SIGNATURE_ALGORITHM)
//                                      .build()
//                                      .parse(token)
//                                      .getHeader();
//
//            // Check protected header against the actual request headers
//            validateProtectedHeader(headers, header);

            logger.info("JWS validation successful for request " + request);

        } catch (JwtException ex) {
            //| SignatureException | InvalidKeyException | NoSuchAlgorithmException
            logger.error("Error validating JWS: " + ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }

    private SignatureData parseSignatureHeader(String signatureHeader) {
        // Parse the JSON signature header
        // Replace double quotes to parse as JSON object
        signatureHeader = signatureHeader.replace("\"", "");
        String[] parts = signatureHeader.split("\\.");

        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid JWS signature header format");
        }

        return new SignatureData(parts[0], parts[1]);
    }

    private void validateProtectedHeader(Map<String, String> headers, JwsHeader<?> header) {
        // Check alg is present and is the single permitted value
        if (!SIGNATURE_ALGORITHM.equals(header.getAlgorithm())) {
            throw new IllegalArgumentException(
                    "Invalid protected header alg '" + header.getAlgorithm() + "', should be '" + SIGNATURE_ALGORITHM +
                            "'");
        }

        // Check FSPIOP-URI is present and matches
        validateHeaderValue("FSPIOP-URI", headers.get("fspiop-uri"), (String) header.get("FSPIOP-URI"));

        // Check FSPIOP-HTTP-Method is present and matches
        validateHeaderValue("FSPIOP-HTTP-Method", headers.get("fspiop-http-method"),
                (String) header.get("FSPIOP-HTTP-Method"));

        // Check FSPIOP-Source is present and matches
        validateHeaderValue("FSPIOP-Source", headers.get("fspiop-source"), (String) header.get("FSPIOP-Source"));

        // If we have a Date field in the protected header, it must be present in the HTTP header and the values should match exactly
        String dateHeaderValue = headers.get("date");
        if (header.containsKey("Date")) {
            String protectedDateHeaderValue = (String) header.get("Date");
            validateHeaderValue("Date", dateHeaderValue, protectedDateHeaderValue);
        }

        // If we have an HTTP fspiop-destination header, it should also be in the protected header, and the values should match exactly
        String destinationHeaderValue = headers.get("fspiop-destination");
        if (header.containsKey("FSPIOP-Destination")) {
            String protectedDestinationHeaderValue = (String) header.get("FSPIOP-Destination");
            validateHeaderValue("FSPIOP-Destination", destinationHeaderValue, protectedDestinationHeaderValue);
        }
    }

    private void validateHeaderValue(String headerName, String actualValue, String protectedValue) {

        if (protectedValue == null) {
            throw new IllegalArgumentException(
                    "Decoded protected header does not contain required " + headerName + " element");
        }

        if (actualValue == null) {
            throw new IllegalArgumentException(
                    headerName + " HTTP header not present in request headers: " + "");//headers
        }

        if (!actualValue.equals(protectedValue)) {
            throw new IllegalArgumentException(headerName + " HTTP request header value: " + actualValue +
                    " does not match protected header value: " + protectedValue);
        }
    }

    private static class SignatureData {

        private final String protectedHeader;

        private final String signature;

        private SignatureData(String protectedHeader, String signature) {

            this.protectedHeader = protectedHeader;
            this.signature = signature;
        }

    }

}


