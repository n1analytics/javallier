[![Build Status](https://travis-ci.org/NICTA/javallier.svg?branch=master)](https://travis-ci.org/NICTA/javallier)

javallier
=========

A Java library for [Paillier partially homomorphic encryption](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
based on [python-paillier](https://github.com/NICTA/python-paillier).

The homomorphic properties of the paillier crypto system are:

- Encrypted numbers can be multiplied by a non encrypted scalar.
- Encrypted numbers can be added together.
- Encrypted numbers can be added to non encrypted scalars.


To use the library add the following dependency to your SBT configuration:

    libraryDependencies += "com.n1analytics" % "javallier_2.10" % "0.4.1"


Example usages are provided in the `/examples` source directory. A benchmarking script
can be found in `/benchmark`.


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

Command Line Tool
-----------------

Run with sbt:

    sbt "runMain com.n1analytics.paillier.cli.Main"


Release
-------

Releases will be signed by Brian Thorne with the PGP key
[C18347DE](https://pgp.mit.edu/pks/lookup?op=vindex&search=0x22ADF3BFC18347DE)

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
