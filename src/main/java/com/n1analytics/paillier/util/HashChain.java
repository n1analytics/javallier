/**
 * Copyright 2015 NICTA
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.n1analytics.paillier.util;

/**
 * A class to store a hashchain
 */
public class HashChain {

  private int hash;

  /**
   * Constructs a new HashChain, initialise the hashcode to 0.
   */
  public HashChain() {
    this.hash = 0;
  }

  /**
   * Chains this HashChain with the hashcode of another object.
   * @param o an object whose hashcode is to be chained to this HashChain.
   * @return this HashChain.
   */
  public HashChain chain(Object o) {
    this.hash = Long.valueOf((((long) this.hash) << 32) | o.hashCode()).hashCode();
    return this;
  }

  /**
   * Returns the hashcode.
   * @return hashcode.
   */
  public int hashCode() {
    return hash;
  }

  @Override
  public boolean equals(Object o) {
    return o == this || (o != null &&
            o instanceof HashChain &&
            hash == ((HashChain) o).hash);
  }
}
