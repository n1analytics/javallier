package com.n1analytics.paillier;

public class PaillierRuntimeException extends RuntimeException {
	private static final long serialVersionUID = 6030736579421587829L;

	public PaillierRuntimeException() { super(); }

	public PaillierRuntimeException(String message) { super(message); }

	public PaillierRuntimeException(Throwable cause) { super(cause); }

	public PaillierRuntimeException(String message, Throwable cause) {
		super(message, cause);
	}

	protected PaillierRuntimeException(
		String message,
		Throwable cause,
		boolean enableSuppression,
		boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
