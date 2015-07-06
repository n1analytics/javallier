#!/bin/sh

sbt 'set testOptions += Tests.Argument(TestFrameworks.JUnit, "--include-categories=com.n1analytics.paillier.SlowTests")' test
