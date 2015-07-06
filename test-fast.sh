#!/bin/sh

sbt 'set testOptions += Tests.Argument(TestFrameworks.JUnit, "--exclude-categories=com.n1analytics.paillier.SlowTests")' test
