import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.MessageFormat;

public class JwtGenerator {

    private static final String SIGNATURE_URL = "/signingmanager/api/v1/keypairs/{0}/sign";

    public static String getSignature(String keypairIDorAlias, String signatureAlg) throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
    {
        String keyPassphrase = System.getenv("SM_CLIENT_CERT_PASSWORD");

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(System.getenv("SM_CLIENT_CERT_FILE").replace("\"", "")),
                keyPassphrase.toCharArray());

        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(keyStore, keyPassphrase.toCharArray())
                .build();

        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(
                sslContext,
                new String[]{"TLSv1.2"},
                null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());

        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf)
                .build();
        String signURL = System.getenv("SM_HOST") + MessageFormat.format(SIGNATURE_URL, keypairIDorAlias);
        HttpPost httpPost = new HttpPost(signURL);
        httpPost.setHeader("x-api-key", System.getenv("SM_API_KEY"));
        httpPost.setHeader("Content-type", "application/json");
        httpPost.setHeader("Accept", "application/json");
        SignatureRequest signatureRequest = new SignatureRequest();
        signatureRequest.setHash(JwtGenerateHash.hash());
        signatureRequest.setSig_alg(signatureAlg);
        httpPost.setEntity(new StringEntity(new ObjectMapper().writeValueAsString(signatureRequest)));
        CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpPost);
        return new ObjectMapper().readValue(EntityUtils.toString(response.getEntity()), SignatureResponse.class).getSignature();
    }

    static class SignatureResponse {
        String id;
        String signature;

        public SignatureResponse() {
        }

        public SignatureResponse(String id, String signature) {
            this.id = id;
            this.signature = signature;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getSignature() {
            return signature;
        }

        public void setSignature(String signature) {
            this.signature = signature;
        }
    }

    static class SignatureRequest {
        String hash;
        String sig_alg;

        public SignatureRequest(String hash, String sig_alg) {
            this.hash = hash;
            this.sig_alg = sig_alg;
        }

        public SignatureRequest() {
        }

        public String getHash() {
            return hash;
        }

        public void setHash(String hash) {
            this.hash = hash;
        }

        public String getSig_alg() {
            return sig_alg;
        }

        public void setSig_alg(String sig_alg) {
            this.sig_alg = sig_alg;
        }
    }

    public static void main(String[] args) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        String keypairAlias = args[0];
        String signatureAlg = args[1];
        var signatureData = getSignature(keypairAlias, signatureAlg);
        String base64Url = Utils.convertToBase64Url(signatureData);

        var header = JwtCreateHeader.createJwtHeader();
        var payload = JwtCreatePayload.createJWtPayload();

        var jwtToken = header + "." + payload + "." + base64Url;
        System.out.println("JWT Token -----> " + jwtToken);
    }


}