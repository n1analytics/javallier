package com.n1analytics.paillier;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.Random;
import java.util.concurrent.TimeUnit;


@State(Scope.Thread)
@Warmup(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
public class JavallierBenchmark {
   
  public static Random rnd = new Random();

  @State(Scope.Benchmark)
  public static class DifferentKeySize {
    @Param({"128", "256", "512", "1024", "2048", "4096"})
    int size;

    PaillierPrivateKey KEY;
    static PaillierContext context;
    double num1;
    double num2;
    EncryptedNumber encryptedNumber1;
    EncryptedNumber encryptedNumber2;
    EncodedNumber encodedNumber2;

    public static Random rnd = new Random();

    @Setup(Level.Iteration)
    public void setup() {
      KEY = PaillierPrivateKey.create(size);
      context = KEY.getPublicKey().createSignedContext();
      num1 = rnd.nextDouble() - 0.5;
      num2 = rnd.nextDouble() - 0.5;
      encryptedNumber1 = context.encrypt(num1);
      encryptedNumber2 = context.encrypt(num2);
      encodedNumber2 = context.encode(num2);
    }

    static EncryptedNumber additiveInverse(EncryptedNumber encryptedNumber1) {
      return context.additiveInverse(encryptedNumber1);
    }

    static PaillierPrivateKey createKey(int size) {
      return PaillierPrivateKey.create(size);
    }

    static EncryptedNumber encryptSafe(PaillierContext context, double num) {
      return context.obfuscate(context.encrypt(num));
    }

    static EncryptedNumber encryptUnsafe(PaillierContext context, double num) {
      return context.encrypt(num);
    }

    static double decrypt(PaillierPrivateKey privateKey, EncryptedNumber encryptedNumber) {
      return encryptedNumber.decrypt(privateKey).decodeDouble();
    }

    static EncryptedNumber addEncryptedEncrypted(EncryptedNumber encryptedNumber1, EncryptedNumber encryptedNumber2) {
      return encryptedNumber1.add(encryptedNumber2);
    }

    static EncryptedNumber addEncryptedEncoded(EncryptedNumber encryptedNumber1, EncodedNumber encodedNumber2) {
      return encryptedNumber1.add(encodedNumber2);
    }

    static EncryptedNumber multiplyEncryptedEncoded(EncryptedNumber encryptedNumber1, EncodedNumber encodedNumber2) {
      return encryptedNumber1.multiply(encodedNumber2);
    }

    @Benchmark
    public void keyGeneration(Blackhole bh) {
      bh.consume(createKey(size));
    }

    @Benchmark
    public void safeEncryption(Blackhole bh) {
      bh.consume(encryptSafe(context, num1));
    }

    @Benchmark
    public void unsafeEncryption(Blackhole bh) {
      bh.consume(encryptUnsafe(context, num1));
    }

    @Benchmark
    public void decryption(Blackhole bh) {
      bh.consume(decrypt(KEY, encryptedNumber1));
    }

    @Benchmark
    public void encryptedAddEncrypted(Blackhole bh) {
      bh.consume(addEncryptedEncrypted(encryptedNumber1, encryptedNumber2));
    }

    @Benchmark
    public void encryptedAddEncoded(Blackhole bh) {
      bh.consume(addEncryptedEncoded(encryptedNumber1, encodedNumber2));
    }

    @Benchmark
    public void encryptedMultiplyEncoded(Blackhole bh) {
      bh.consume(multiplyEncryptedEncoded(encryptedNumber1, encodedNumber2));
    }

    @Benchmark
    public void encryptedAdditiveInverse(Blackhole bh) {
      bh.consume(additiveInverse(encryptedNumber1));
    }
  }

  //for comparison, we measure add and multiply on doubles
  @State(Scope.Benchmark)
  public static class Doubles{
    double d1, d2;
    @Setup(Level.Invocation)
    public void setup(){
      d1 = rnd.nextDouble() - 0.5;
      d2 = rnd.nextDouble() - 0.5;
    }
  }
  
  @Benchmark public double doublePrecicionAdd(Doubles ds){
    return ds.d1+ds.d2;
  }
  
  @Benchmark public double doublePrecicionMultiply(Doubles ds){
    return ds.d1*ds.d2;
  }

}
