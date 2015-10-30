[![Build Status](https://travis-ci.org/NICTA/javallier.svg?branch=master)](https://travis-ci.org/NICTA/javallier)

javallier
=========

A Java library for Paillier partially homomorphic encryption 
based on [python-paillier](https://github.com/NICTA/python-paillier).

Build
-----

Compile the library:

    $ sbt compile
    
Create a jar file:

    $ sbt package
    

Run all tests with `sbt`:

    $ sbt test
    
Or run just fast tests:

    $ ./test-fast.sh

Release
-------

* http://www.scala-sbt.org/release/docs/Using-Sonatype.html
* http://central.sonatype.org/pages/releasing-the-deployment.html


Limitations
-----------

*   Arithmetic functions that involve a combination of addition and multiplication operations, such as 
    (a + b) &times; c, might result in overflow in the `EncryptedNumber` domain. When overflow occurs, the computation 
    result is incorrect even though the the result was succesfully decrypted and decoded. At the moment, the 
    implementation does not detect overflow cause by such computation. 
    
    One way to detect this is to ensure that the inputs to the function are carefully chosen such that it does not 
    lead to overflow. For more complex arithmetic functions, such approach may not be possible. The alternative is to 
    initially perform the same arithmetic function in the `Number` domain and check whether the result is a valid 
    `Number`. The computation in the `EncryptedNumber` domain should only be performed if the result in the  the 
    `Number` domain is valid.
