package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.FileReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class RSAKeyProvider {

    @Autowired
    private ResourceLoader resourceLoader;

    public static PublicKey getPublicKeyRsa(String sKeyID) throws NoSuchAlgorithmException, InvalidKeySpecException {
//        //TODO : Replace your public key here
//        sKeyID = sKeyID.replaceAll("\n", "");
//        sKeyID = sKeyID.replaceAll(" ", "");
//        var decodedKey = Base64.getEncoder().encodeToString(sKeyID.getBytes());
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(sKeyID.getBytes()); //Base64.getDecoder().decode(sKeyID)
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PublicKey publicKey = kf.generatePublic(keySpec);
//        return publicKey;

        String orig =
                "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBMk5pKytLeUpVaDhLYklLVU51OG0KUk5lRCtrU2tXZEh6MjBvSFZYK0g0cVd4WHlJSTk0MVdJUFU2WFpPc3lMeE9qZU1hb0ZRanJ6bDFwYnZQekUyRQpwMmhlK1BnQ1JteDNqOFlMVVd3dGpuQTVwTTFLWDhpNG5vTUw4RmlWY1U2NkE5RjRkZmRQR2MzY0tQQ2ZPbnorCmtBbW5qRllzajYzRCsrTThYSDRWaS9Vc0V3T1lzU05FR2RncUd2OTlTNHpVRzFzd2FqZ1NnODhvbTVaOC9Ja1AKY01LT3cvWkpvVHNDN3l1VlJnTC9xa3EwaDVkM2lXVXNNdXl1K0xoblRhTko4bW9WQmpJT2lQQkR0cEQyN1lzNgpCSGs1dEdBa3ZHZDg0N3c4SjVEeTFzYWlQS0pxelltcUx5akg3b3VlcERFczdEZ2UxZUlJeno5a1RnSkhKZHVzCnd3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K";

        String pem = new String(Base64.getDecoder().decode(orig)); // default cs okay for PEM
        String[] lines = pem.split("\n");
        lines[0] = lines[lines.length - 1] = "";
        String body = String.join("", lines);
        // in general split on "\r?\n" (or delete "\r" and split on "\n")
        //or instead:
        //String body = pem.replaceAll("-----(BEGIN|END) RSA PUBLIC KEY-----\n","").replaceAll("\n", ""); // or "\r?\n"

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(body)));
        return key;
    }

    public static PrivateKey getPrivateKeyRsa(String sKeyID) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //TODO : Replace your private key here
        var decodedKey = Base64.getEncoder().encodeToString(sKeyID.getBytes());
        PKCS8EncodedKeySpec keySpec =
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(decodedKey)); //Base64.getDecoder().decode(sKeyID)
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return privateKey;

    }

    public PublicKey readX509PublicKey(String publicKeyPath) throws Exception {

//        Resource resource = new ClassPathResource("data/" + publicKeyPath);
//        File file = resource.getFile();

        //File file = ResourceUtils.getFile("classpath:" + publicKeyPath);

//        ClassLoader classLoader = getClass().getClassLoader();
//        var url = classLoader.getResource(publicKeyPath).getPath();

        //Path path = Paths.get(getClass().getClassLoader().getResource(publicKeyPath).toURI());

        //Resource resource = resourceLoader.getResource("classpath:" + publicKeyPath);

        //Resource resource = new ClassPathResource("/data/" + publicKeyPath, this.getClass().getClassLoader());

        var resource = RSAKeyProvider.class.getClassLoader().getResourceAsStream(publicKeyPath);
        System.out.println(resource);

        try (FileReader keyReader = new FileReader(publicKeyPath)) {
            StringBuilder keyPem = new StringBuilder();
            int ch;
            while ((ch = keyReader.read()) != -1) {
                keyPem.append((char) ch);
            }

            String key = keyPem.toString();  //new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

            String publicKeyPEM = key
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");

            byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return keyFactory.generatePublic(keySpec);
        }
    }

    public PrivateKey readPKCS8PrivateKey(String privateKeyPath) throws Exception {

        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

//        Resource resource = new ClassPathResource("data/" + privateKeyPath);
//        File file = resource.getFile();

//        ClassLoader classLoader = getClass().getClassLoader();
//        var url = classLoader.getResource(privateKeyPath).getPath();

        // File file = ResourceUtils.getFile("classpath:" + privateKeyPath);

        // Path path = Paths.get(getClass().getClassLoader().getResource(privateKeyPath).toURI());

        //Resource resource = resourceLoader.getResource("classpath:" + privateKeyPath);
        // Resource resource = new ClassPathResource(privateKeyPath);

        // Resource resource = new ClassPathResource("/data/" + privateKeyPath, this.getClass().getClassLoader());

        var resource = RSAKeyProvider.class.getClassLoader().getResourceAsStream(privateKeyPath);
        System.out.println(resource);

        try (FileReader keyReader = new FileReader(privateKeyPath)) {
            StringBuilder keyPem = new StringBuilder();
            int ch;
            while ((ch = keyReader.read()) != -1) {
                keyPem.append((char) ch);
            }

            String key = keyPem.toString(); //new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

            String privateKeyPEM = key
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END RSA PRIVATE KEY-----", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return keyFactory.generatePrivate(keySpec);
        }

//        try (PemReader pemReader = new PemReader(new BufferedReader(new FileReader(privateKeyPath)))) {
//
//            PemObject pemObject = pemReader.readPemObject();
//            byte[] content = pemObject.getContent();
//
//            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(content);
//            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//            return keyFactory.generatePrivate(keySpec);
//        }
    }

}
