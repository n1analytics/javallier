package com.n1analytics.paillier.cli;

import org.apache.commons.cli.CommandLine;

import java.io.*;

public class OptionParsing {

  public static Writer processOutputOption(CommandLine line) throws FileNotFoundException {
    Writer output;
    String outputFilename = null;

    if(line.hasOption("output")) {
      outputFilename = line.getOptionValue("output");
    }

    if (outputFilename != null && !"-".equals(outputFilename)) {
      output = (Writer) new PrintWriter(outputFilename);
    } else {
      output = (Writer) new BufferedWriter(new OutputStreamWriter(System.out));
    }
    return output;
  }
}
