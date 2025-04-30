package io.dyuti.jwt;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Vert.x JWT token generator
 */
@Command(name = "token-generator", mixinStandardHelpOptions = true, version = "1.0",
    description = "Generates a JWT token using the provided public and private keys")
public class App implements Callable<Integer> {

  private static final Logger log = LoggerFactory.getLogger("token-generator");

  @Option(names = {"-p",
      "--public"}, required = true, description = "Path to public key (in pem format)")
  private String publicKey;

  @Option(names = {"-s",
      "--private"}, required = true, description = "Path to private key (in pem format)")
  private String privateKey;

  @Option(names = {"-a", "--audience"}, description = "Audience")
  private String audience;

  @Option(names = {"-i", "--issuer"}, required = true, description = "Issuer")
  private String issuer;

  @Option(names = {"-u", "--subject"}, required = true, description = "Subject")
  private String subject;

  @Option(names = {"-e", "--expiry"}, description = "Expiry in years")
  private Integer expiry;

  @Option(names = {"-n", "--noExpiry"}, description = "No Expiry")
  private boolean noExpiry;

  @Option(names = {"-c", "--claims"}, description = "Custom claims Ex: claim:claim value")
  private String claims;

  @Option(names = {"-o", "--operation"}, description = "Operation to perform")
  private Operation operation;

  @Option(names = {"-t", "--token"}, description = "Token to verify")
  private String tokenToBeVerified;

  public Integer call() {
    try {
      String publicKeyData = Files.readString(Paths.get(publicKey))
          .replace("-----BEGIN PUBLIC KEY-----\n", "")
          .replace("-----END PUBLIC KEY-----\n", "")
          .replaceAll("\\s", "");
      String privateKeyData = Files.readString(Paths.get(privateKey))
          .replace("-----BEGIN PRIVATE KEY-----\n", "")
          .replace("-----END PRIVATE KEY-----\n", "")
          .replaceAll("\\s", "");
      KeyPair keyPair = loadKeyPair(privateKeyData, publicKeyData);
      if (operation == null) {
        operation = Operation.GENERATE;
      }
      if (operation == Operation.GENERATE) {
        final String token = generate(keyPair, issuer, subject, audience, claims, noExpiry,
            Objects.isNull(expiry) ? 0 : expiry);
        verifyToken(token, keyPair);
      }
      if (operation == Operation.VERIFY) {
        verifyToken(tokenToBeVerified, keyPair);
      }
      return 0;
    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | JoseException e) {
      log.error("Error generating token!", e);
      return -1;
    }
  }

  private static JwtClaims buildClaims(String issuer, String subject, String audience,
      String claims, boolean noExpiry, int expiry) {
    var jwtClaims = new JwtClaims();
    jwtClaims.setIssuer(issuer);
    jwtClaims.setSubject(subject);
    jwtClaims.setIssuedAtToNow();
    if (Objects.nonNull(audience)) {
      jwtClaims.setAudience(Arrays.asList(audience.split(",")));
    }
    if (noExpiry) {
      jwtClaims.setExpirationTimeMinutesInTheFuture(26280000);
    } else {
      //Minutes in 1 year = 525600
      jwtClaims.setExpirationTimeMinutesInTheFuture((expiry * 525600));
    }
    if (Objects.nonNull(claims)) {
      String[] claimTokens = claims.split(",");
      for (String c : claimTokens) {
        String[] claimToken = c.split(":");
        jwtClaims.setClaim(claimToken[0], claimToken[1]);
      }
    }
    return jwtClaims;
  }

  private static String generate(KeyPair keyPair, String issuer, String subject,
      String audience, String claims, boolean noExpiry, int expiry) throws JoseException {
    var signedToken = signToken(keyPair, issuer, subject, audience, claims, noExpiry, expiry);
    return encryptToken(keyPair, signedToken);
  }

  private static String signToken(KeyPair keyPair, String issuer, String subject,
      String audience, String claims, boolean noExpiry, int expiry) throws JoseException {
    var jws = new JsonWebSignature();
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
    jws.setKey(keyPair.getPrivate());
    var jwtClaims = buildClaims(issuer, subject, audience, claims, noExpiry, expiry);
    jws.setPayload(jwtClaims.toJson());
    return jws.getCompactSerialization();
  }

  private static String encryptToken(KeyPair keyPair, String token) throws JoseException {
    var jwe = new JsonWebEncryption();
    jwe.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
    jwe.setKey(keyPair.getPublic());
    jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
    jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
    jwe.setContentTypeHeaderValue("JWT");
    jwe.setPayload(token);
    return jwe.getCompactSerialization();
  }

  private static String decryptToken(String token, KeyPair keyPair) throws JoseException {
    var jwe = new JsonWebEncryption();
    jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
    jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
    jwe.setCompactSerialization(token);
    jwe.setKey(keyPair.getPrivate());
    return jwe.getPayload();
  }


  public static KeyPair loadKeyPair(String privateKeyContent, String publicKeyContent)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    // Load private key
    byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);
    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
    // Load public key
    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
    return new KeyPair(publicKey, privateKey);
  }

  public static void main(String[] args) {
    int exitCode = new picocli.CommandLine(new App()).execute(args);
    System.exit(exitCode);
  }

  /**
   * Verify Token
   */
  private static void verifyToken(String token, KeyPair keyPair) {
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setRequireExpirationTime()
        .setAllowedClockSkewInSeconds(30)
        .setVerificationKey(keyPair.getPublic())
        .setExpectedAudience("ROLE_ADMIN", "ROLE_USER", "ROLE_OPERATOR")
        .build();
    try {
      JwtClaims claims = jwtConsumer.processToClaims(decryptToken(token, keyPair));
      log.info("Token: {}", token);
      log.info("Token Claims:");
      log.info("------------------------------------------------------------");
      log.info("Subject: {}", claims.getSubject());
      log.info("Issuer: {}", claims.getIssuer());
      log.info("Issued At: {}", claims.getIssuedAt());
      log.info("Expiration: {}", claims.getExpirationTime());
      // Audience
      if (claims.getAudience().isEmpty()) {
        log.info("No audience found");
      } else {
        if(log.isInfoEnabled()) {
          log.info("Audience: {}", String.join(", ", claims.getAudience()));
        }
      }
      var claimsMap = claims.getClaimsMap(Set.of("sub", "iss", "iat", "exp", "jti", "aud"));
      if (claimsMap.isEmpty()) {
        log.info("No claims found");
      } else {
        log.info("Claims:");
        for (var entry : claimsMap.entrySet()) {
          log.info("{}: {}", entry.getKey(), entry.getValue());
        }
      }
      log.info("------------------------------------------------------------");
    } catch (Exception e) {
      log.error("Token verification failed: ", e);
    }
  }
}
