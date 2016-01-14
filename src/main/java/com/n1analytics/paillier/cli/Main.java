package com.n1analytics.paillier.cli;


public class Main {

  public static void main(String[] args) {
    System.out.println("Javallier CLI - Data61 - 2016");

    new JavallierCLI(args).parse();

  }

}
