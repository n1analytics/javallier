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

package com.n1analytics.paillier.examples

import com.n1analytics.paillier._

object PrivateSum {
  def main(args: Array[String]): Unit = {


    val rawNumbers = Array(0.0, 0.8, 1.0, 3.2, -5, 50)

    val keypair = PaillierPrivateKey.create(1024)
    var publicKey = keypair.getPublicKey

    val paillierContext = publicKey.createSignedContext

    println("Encrypting doubles with public key (e.g., on multiple devices)")
    val encryptedNumbers = rawNumbers.map(n => paillierContext.encrypt(n))

    println("Adding encrypted doubles")
    val encryptedSum = encryptedNumbers.reduce((n1, n2) => n1.add(n2))

    println("Decrypting result:")
    println(keypair.decrypt(encryptedSum).decodeDouble)

  }
}