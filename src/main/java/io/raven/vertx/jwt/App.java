package io.raven.vertx.jwt;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Vert.x JWT token generator
 */
public class App {

  private static final Logger log = LoggerFactory.getLogger("jwt-token-gen");

  public static void main(String[] args) {
    // create the command line parser
    CommandLineParser parser = new DefaultParser();
    CommandLine commandLine = null;
    // create the Options
    Options options = new Options();
    options.addRequiredOption( "m", "algo", true, "Algorithm");
    options.addRequiredOption( "p", "public", true, "Path to public key (in pem format)" );
    options.addRequiredOption( "s", "private", true, "Path to private key (in pem format)");
    options.addOption( "a", "audience", true, "Audience");
    options.addRequiredOption( "i", "issuer", true, "Issuer");
    options.addRequiredOption( "u", "subject", true, "Subject");
    options.addOption( "e", "expiry", true, "Expiry in seconds");
    options.addOption( "n", "noExpiry", false, "No Expiry");
    options.addOption( "c", "claims", true, "Custom claims Ex: claim:claimvalue");
    options.addOption( "r", "permissions", true, "Comma separated list of permissions");
    try {
      commandLine = parser.parse(options, args, true);
    } catch(ParseException e) {
      showHelp(options);
      System.exit(0);
    }
    try {
      String publicKey = Files.readString(Paths.get(commandLine.getOptionValue("p")))
          .replace("-----BEGIN PUBLIC KEY-----\n", "")
          .replace("-----END PUBLIC KEY-----\n", "");
      String privateKey = Files.readString(Paths.get(commandLine.getOptionValue("s")))
          .replace("-----BEGIN PRIVATE KEY-----\n", "")
          .replace("-----END PRIVATE KEY-----\n", "");
      Vertx vertx = Vertx.vertx();
      JWTAuthOptions config = new JWTAuthOptions()
          .addPubSecKey(new PubSecKeyOptions(
              new JsonObject()
                .put("algorithm", commandLine.getOptionValue("m"))
                .put("publicKey", publicKey)
                .put("secretKey", privateKey)
          ));
      JWTAuth provider = JWTAuth.create(vertx, config);
      JWTOptions jwtOptions = new JWTOptions();
      jwtOptions.setAlgorithm(commandLine.getOptionValue("m"));
      JsonObject claims = new JsonObject();
      if(commandLine.hasOption('a')) {
        jwtOptions.setAudience(Arrays.asList(commandLine.getOptionValue('a').split(",")));
      }
      jwtOptions.setIssuer(commandLine.getOptionValue("i"));
      jwtOptions.setSubject(commandLine.getOptionValue("u"));
      if (commandLine.hasOption("n")) {
        jwtOptions.setExpiresInMinutes(26280000);
      } else {
        jwtOptions.setExpiresInSeconds(Integer.parseInt(commandLine.getOptionValue("e")));
      }
      if(commandLine.hasOption('c')) {
        String[] claimTokens = commandLine.getOptionValue('c').split(",");
        for(String c : claimTokens) {
          String[] claimToken = c.split(":");
          claims.put(claimToken[0], claimToken[1]);
        }
      }
      if(commandLine.hasOption('r')) {
        jwtOptions.setPermissions(Arrays.asList(commandLine.getOptionValues('r')));
      }
      final String token = provider.generateToken(claims, jwtOptions);
      log.debug("JWT Options: " +jwtOptions.toJSON().encodePrettily());
      log.debug("JWT Claims: " +claims.encodePrettily());
      log.info("Token: " + token);
    } catch(IOException e) {
      log.error("Error generating token!", e);
    }
  }

  private static void showHelp(Options options) {
    HelpFormatter formatter = new HelpFormatter();
    formatter.printHelp("java -jar jwt-token-gen-0.1-shaded.jar", options);
  }
}
