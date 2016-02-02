package com.n1analytics.paillier.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import com.n1analytics.paillier.util.BigIntegerUtil;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * A simple command line interface to Javallier using the public API.
 *
 * This is not meant to be a full featured command line interface or shell but to
 * illustrate how to do some simple operations and to be used for testing integration
 * between different Paillier cryptosystem implementations.
 */
public class JavallierCLI {

  private static final Logger log = Logger.getLogger(JavallierCLI.class.getName());

  private String[] args = null;
  private Options options = new Options();

  public JavallierCLI(String[] args) {
    this.args = args;

    // create the global Options
    options.addOption("h", "help", false, "HELP");
    options.addOption("v", "verbose", false, "Enable logging");
//    options.addOption("o", "output", true, "Output to given file instead of stdout");

  }

  public void parse() {

    // Create a list of commands that are supported. Each
    // command defines a run method and some methods for
    // printing help.
    // See the definition of each command below.
    HashMap<String, Command> commands = new HashMap<String, Command>();

    commands.put("genpkey", new GenerateKeyPairCommand("genpkey"));
    commands.put("extract", new ExtractCommand("extract"));
    commands.put("encrypt", new EncryptCommand("encrypt"));
    commands.put("decrypt", new DecryptCommand("decrypt"));
    commands.put("add", new AddCommand("add"));
    commands.put("addenc", new AddEncCommand("addenc"));

    Optional<Command> command = Optional.empty();

    List<String> argsList = Arrays.asList(args);
    List<String> leftOverArgs;
    if (argsList.size() > 0) {
      // Ensure that we have a valid command
      String probableCommand = argsList.get(0);
      if (commands.containsKey(probableCommand)) {
        command = Optional.ofNullable(commands.get(probableCommand));
      }
    }

    // create the arg parser
    CommandLineParser parser = new DefaultParser();

    // parse the top level command line arguments
    try {
      command.ifPresent(c -> options = c.addOptions(options));
      CommandLine line = parser.parse(options, args);

      // Process top level options

      // Setup logging to console
      Handler systemOut = new ConsoleHandler();
      systemOut.setLevel( Level.ALL );
      log.addHandler(systemOut);

      if (line.hasOption("v")) {
        log.setLevel(Level.INFO);
      } else {
        log.setLevel(Level.WARNING);
      }
      // Prevent logs from processed by default Console handler.
      log.setUseParentHandlers(false);

      if (line.hasOption("help") || !command.isPresent()) {
        if ( !command.isPresent()) {
          help(commands.values());
        } else {
          // If there is a command listed (e.g. genpkey --help)
          // then show the help for that command
          help(command.get());
        }

      }

      // At this point we must have a command
      Command cmd = command.get();
      cmd.processOptions(line);

      // Capture the arguments to be passed to the command
      leftOverArgs = line.getArgList();

      try {
        cmd.run(leftOverArgs);
      } catch (Exception e) {
        log.warning("Failed to run command. Reason: " + e.getMessage());
        e.printStackTrace();
      }

    } catch (ParseException exp) {
      // oops, something went wrong
      System.err.println("Parsing failed.  Reason: " + exp.getMessage());
      // print the list of available options
      help(commands.values());
    }

  }

  /**
   * Print the usage for a specific command.
   * @param command The command whose usage you want to print.
   */
  public static void usage(Command command) {
    System.out.println("Usage: pheutil " + command.getName() + " " + command.getOptionDescription());
  }

  /**
   * Prints the help for a specific command.
   * @param command The command whose help you want to print.
   */
  public static void help(Command command) {
    usage(command);
    System.out.println();
    System.out.println(command.getDescription());

    System.exit(0);
  }

  /** Prints overall program help. */
  private void help(Collection<Command> commands) {
    HelpFormatter formatter = new HelpFormatter();
    formatter.printHelp("pheutil", options);

    System.out.println("");
    System.out.println("Commands:");
    System.out.println("");
    for (Command command : commands) {
      System.out.println("    " + command.getName() + ": " + command.getBlurb());
    }
    System.out.println("");
    System.out.println("Try pheutil COMMAND --help for command usage.");

    System.exit(0);
  }


  /**
   * An exception that is thrown when invalid arguments are
   * passed to a command.
   */
  protected static class InvalidArgsException extends Exception {
    private List<String> args;

    public InvalidArgsException(List<String> args) {
      this.args = args;
    }

    public List<String> getArgs() {
      return this.args;
    }
  }

  /**
   * Defines the interface for commands that can be run by the CLI
   */
  protected static abstract class Command {
    private String name;

    public Command(String name) {
      this.name = name;
    }

    public String getName() {
      return name;
    }

    /**
     * Run the command.
     * @param args A list of args to the command.
     */
    public abstract void run(List<String> args) throws InvalidArgsException, IOException;

    /**
     * Add any command specific options to the argument parser
     * */
    public Options addOptions(Options options) {
      return options;
    }

    public void processOptions(CommandLine line) {
      log.info("Ignoring command specific options");
    }

    /**
     * Gets a string describing command line arguments of the command.
     * Used when printing usage and help.
     */
    public abstract String getOptionDescription();

    /**
     * Gets a short string describing what the command does.
     * Used when printing usage and help.
     */
    public abstract String getBlurb();

    /**
     * Gets a verbose string describing how to use the command.
     * Used when printing command specific usage and help.
     */
    public abstract String getDescription();
  }


  /**
   * This command creates a new paillier keypair
   */
  protected static class GenerateKeyPairCommand extends Command {

    int DEFAULT_KEYSIZE = 2048;
    int keysize;

    String comment;

    protected class PublicKeyJsonSerialiser implements PaillierPublicKey.Serializer {
      // container object node
      ObjectNode data;
      ObjectMapper mapper;

      PublicKeyJsonSerialiser() {
        mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

      }

      public ObjectNode getNode() {
        return data;
      }

      @Override
      public String toString() {
        return data.toString();
      }

      @Override
      public void serialize(BigInteger modulus) {
        data = mapper.createObjectNode();
        data.put("alg", "PAI-GN1");
        data.put("kty", "DAJ");
        data.put("kid", "Paillier public key generated by javallier on TODO");

        // Convert n to base64 encode
        String encodedModulus = new String(Base64.encodeBase64(modulus.toByteArray()));
        data.put("n", encodedModulus);

        ArrayNode an = data.putArray("key_ops");
        an.add("encrypt");
      }
    }

    protected class PrivateKeyJsonSerialiser implements PaillierPrivateKey.Serializer {
      ObjectMapper mapper;
      ObjectNode data;

      public PrivateKeyJsonSerialiser() {
        mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
      }

      @Override
      public String toString() {
        return data.toString();
      }

      @Override
      public void serialize(PaillierPublicKey publickey, BigInteger p, BigInteger q) {
        data = mapper.createObjectNode();
        data.put("kty", "DAJ");
        ArrayNode an = data.putArray("key_ops");
        an.add("decrypt");

        PublicKeyJsonSerialiser serialisedPublicKey = new PublicKeyJsonSerialiser();
        publickey.serialize(serialisedPublicKey);
        data.set("pub", serialisedPublicKey.getNode());

        data.put("kid", "Paillier private key generated by javallier on TODO");

        BigInteger lambda = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        String encodedLambda = new String(Base64.encodeBase64(lambda.toByteArray()));
        data.put("lambda", encodedLambda);

        BigInteger mu = BigIntegerUtil.invert(lambda, publickey.getModulus());
        String encodedMu = new String(Base64.encodeBase64(mu.toByteArray()));
        data.put("mu", encodedMu);
      }

    }

    public GenerateKeyPairCommand(String name) {
      super(name);
    }

    public void run(List<String> args) {

      PaillierPrivateKey privateKey = PaillierPrivateKey.create(keysize);
      log.info("Keypair generated");

      PrivateKeyJsonSerialiser serializedPrivateKey = new PrivateKeyJsonSerialiser();
      privateKey.serialize(serializedPrivateKey);

      String outputFile;
      if( args.size() < 2) {
        log.info("Output to stdout?");

        // Output to file/stream
        System.out.println(serializedPrivateKey);

      } else {
        outputFile = args.get(1);
        log.info("Using destination of " + outputFile);
        try(PrintWriter out = new PrintWriter(outputFile)) {
          out.println(serializedPrivateKey);
        } catch (FileNotFoundException e) {
          log.info("Couldn't find that location sorry.");
        }
      }

    }

    public Options addOptions(Options options) {
      options.addOption("s", "keysize", true, "The keysize in bits. Default to 1024");
      options.addOption("m", "message", true, "Add an identifying comment to the key");
      return options;
    }

    public void processOptions(CommandLine line) {
      if(line.hasOption("keysize")) {
        keysize = Integer.parseInt(line.getOptionValue("keysize"));
        log.info("Using provided key size of " + keysize);
      } else {
        keysize = DEFAULT_KEYSIZE;
        log.info("Using default key size of " + keysize);
      }

      if(line.hasOption("message")) {
        comment = line.getOptionValue("message");
      } else {
        comment = "";
      }
      log.info("Comment: " + comment);
    }

    public String getOptionDescription() {
      return "[--keysize=KEYSIZE] OUTPUT";
    }

    public String getBlurb() {
      return "Create a new paillier keypair";
    }

    public String getDescription() {
      return "Generate a new public/private keypair for use in\n" +
             "paillier operations.\n" +
             "Output in JSON Web Key format\n" +
             "https://tools.ietf.org/html/rfc7517";
    }
  }


  /**
   * This command encrypts a plaintext value with a paillier
   * public key.
   */
  protected static class EncryptCommand extends Command {

    public EncryptCommand(String name) {
      super(name);
    }

    public void run(List<String> args) {
      System.out.println("Running the encrypt command");
      System.out.println(args);
    }

    public String getOptionDescription() {
      return "PUBLICKEY";
    }

    public String getBlurb() {
      return "Encrypt a value with the given public key";
    }

    public String getDescription() {
      return "Encrypt a value with the given public key\n" +
             "Value can be an integer or float.";
    }
  }


  /**
   * This command decrypts a ciphertext value with a paillier
   * private key.
   */
  protected static class DecryptCommand extends Command {

    public DecryptCommand(String name) {
      super(name);
    }

    public void run(List<String> args) {
      System.out.println("Running the decrypt command");
      System.out.println(args);
    }

    public String getOptionDescription() {
      return "PRIVATEKEY ENCRYPTED";
    }

    public String getBlurb() {
      return "Decrypt ENCRYPTED using PRIVATEKEY";
    }

    public String getDescription() {
      return "Decrypted value could be an integer or float.";
    }
  }

  /**
   * This command extracts the public key from a private key.
   */
  protected static class ExtractCommand extends Command {

    public ExtractCommand(String name) {
      super(name);
    }

    public void run(List<String> args) {
      log.info("Running the extract command");
      log.info("Args: " + args);

      String privatefn = args.get(1);
      String publicfn = args.get(2);

      Writer out;

      final ObjectMapper mapper = new ObjectMapper();
      try {

        if(publicfn.equals("-")) {
          out = new BufferedWriter(new OutputStreamWriter(System.out));
        } else {
          out = new PrintWriter(publicfn);
        }

        final Map privateKey = mapper.readValue(new File(privatefn), Map.class);
        mapper.writeValue(out, privateKey.get("pub"));
      } catch (IOException e) {
        e.printStackTrace();
      }

    }

    public String getOptionDescription() {
      return "PRIVATEKEY OUTPUT";
    }

    public String getBlurb() {
      return "Extract the public key from a PRIVATE key";
    }

    public String getDescription() {
      return "Extract the public key from a private key";
    }
  }

  /**
   * This command adds a plaintext number to an encrypted
   * number.
   */
  protected static class AddCommand extends Command {

    public AddCommand(String name) {
      super(name);
    }

    public void run(List<String> args) {
      System.out.println("Running the add command");
      System.out.println(args);
    }

    public String getOptionDescription() {
      return "PUBLICKEY ENCRYPTED PLAINTEXT";
    }

    public String getBlurb() {
      return "Add ENCRYPTED to PLAINTEXT";
    }

    public String getDescription() {
      return "Add ENCRYPTED and PLAINTEXT numbers together \n" +
              "producing a new encrypted number.";
    }
  }

  /**
   * This command adds two encrypted numbers together.
   */
  protected static class AddEncCommand extends Command {

    public AddEncCommand(String name) {
      super(name);
    }

    public void run(List<String> args) {
      System.out.println("Running the addenc command");
      System.out.println(args);
    }

    public String getOptionDescription() {
      return "PUBLICKEY ENCRYPTED1 ENCRYPTED2";
    }

    public String getBlurb() {
      return "Add ENCRYPTED1 to ENCRYPTED2";
    }

    public String getDescription() {
      return "Add two encrypted numbers together \n" +
              "producing a new encrypted number.";
    }
  }

}