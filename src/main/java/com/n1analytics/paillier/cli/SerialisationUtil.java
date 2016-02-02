package com.n1analytics.paillier.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.n1analytics.paillier.EncryptedNumber;

/**
 * Class for common serialisation utils used in the CLI.
 * */
public class SerialisationUtil {

  public static ObjectNode serialise_encrypted(EncryptedNumber enc) {
    ObjectNode data;
    ObjectMapper mapper = new ObjectMapper();
    data = mapper.createObjectNode();
    data.put("v", enc.calculateCiphertext().toString());
    data.put("e", enc.getExponent());
    return data;
  }

}
