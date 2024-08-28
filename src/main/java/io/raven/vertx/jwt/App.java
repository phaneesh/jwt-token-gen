package io.raven.vertx.jwt;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Vert.x JWT token generator
 */
@Command(name = "token-generator", mixinStandardHelpOptions = true, version = "1.0",
    description = "Generates a JWT token using the provided public and private keys")
public class App implements Callable<Integer> {

  private static final Logger log = LoggerFactory.getLogger("token-generator");

  @Option(names = {"-m", "--algo"}, required = true, description = "Algorithm")
  private String algorithm;

  @Option(names = {"-p", "--public"}, required = true, description = "Path to public key (in pem format)")
  private String publicKey;

  @Option(names = {"-s", "--private"}, required = true, description = "Path to private key (in pem format)")
  private String privateKey;

  @Option(names = {"-a", "--audience"}, description = "Audience")
  private String audience;

  @Option(names = {"-i", "--issuer"}, required = true, description = "Issuer")
  private String issuer;

  @Option(names = {"-u", "--subject"}, required = true, description = "Subject")
  private String subject;

  @Option(names = {"-e", "--expiry"}, description = "Expiry in seconds")
  private Integer expiry;

  @Option(names = {"-n", "--noExpiry"}, description = "No Expiry")
  private boolean noExpiry;

  @Option(names = {"-c", "--claims"}, description = "Custom claims Ex: claim:claim value")
  private String claims;

  @Option(names = {"-r", "--permissions"}, description = "Comma separated list of permissions")
  private String permissions;

  public Integer call() {
    try {
      String publicKeyData = Files.readString(Paths.get(publicKey))
          .replace("-----BEGIN PUBLIC KEY-----\n", "")
          .replace("-----END PUBLIC KEY-----\n", "");
      String privateKeyData = Files.readString(Paths.get(privateKey))
          .replace("-----BEGIN PRIVATE KEY-----\n", "")
          .replace("-----END PRIVATE KEY-----\n", "");
    Vertx vertx = Vertx.vertx();
    JWTAuthOptions config = new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions(
            new JsonObject()
                .put("algorithm", algorithm)
                .put("publicKey", publicKeyData)
                .put("secretKey", privateKeyData)
        ));
    JWTAuth provider = JWTAuth.create(vertx, config);
    JWTOptions jwtOptions = new JWTOptions();
    jwtOptions.setAlgorithm(algorithm);
    JsonObject claimsObject = new JsonObject();
    if (Objects.nonNull(audience)) {
      jwtOptions.setAudience(Arrays.asList(audience.split(",")));
    }
    jwtOptions.setIssuer(issuer);
    jwtOptions.setSubject(subject);
    if (noExpiry) {
      jwtOptions.setExpiresInMinutes(26280000);
    } else {
      jwtOptions.setExpiresInSeconds(expiry);
    }
    if(Objects.nonNull(claims)) {
      String[] claimTokens = claims.split(",");
      for(String c : claimTokens) {
        String[] claimToken = c.split(":");
        claimsObject.put(claimToken[0], claimToken[1]);
      }
    }
    if(Objects.nonNull(permissions)) {
      jwtOptions.setPermissions(Arrays.asList(permissions.split(",")));
    }
    final String token = provider.generateToken(claimsObject, jwtOptions);
    log.debug("JWT Options: " +jwtOptions.toJSON().encodePrettily());
    log.debug("JWT Claims: " +claimsObject.encodePrettily());
    log.info("Token: " + token);
    return 0;
    } catch(IOException e) {
      log.error("Error generating token!", e);
      return -1;
    }
  }

  public static void main(String[] args) {
    int exitCode = new picocli.CommandLine(new App()).execute(args);
    System.exit(exitCode);
  }
}
