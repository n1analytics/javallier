package com.n1analytics.paillier;

public interface TwoInputsFunction<T1, T2, R> {
    public R eval(T1 arg1, T2 arg2);
}