
# CLI Test

This is the test framework for Javallier Command Line Interface (CLI) executable 
(developed using Python 3).

To run, generate `javallier.jar` using:

    sbt assembly

The jar file is available in `target/scala-2.10/`.
 
Then run the tests:

    python src/test/cli/cliTest.py

Note: the tests take around 400 to 450 seconds to complete. 