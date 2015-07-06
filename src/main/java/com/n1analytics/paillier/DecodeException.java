package com.n1analytics.paillier;

public class DecodeException extends PaillierRuntimeException {
	private static final long serialVersionUID = 2613143080120141130L;

	public DecodeException() { super(); }

	public DecodeException(String message) { super(message); }

	public DecodeException(Throwable cause) { super(cause); }

	public DecodeException(String message, Throwable cause) {
		super(message, cause);
	}

	public DecodeException(
		String message,
		Throwable cause,
		boolean enableSuppression,
		boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
