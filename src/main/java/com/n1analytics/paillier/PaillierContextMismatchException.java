package com.n1analytics.paillier;

public class PaillierContextMismatchException extends PaillierKeyMismatchException {
	private static final long serialVersionUID = -6169034734530199098L;

	public PaillierContextMismatchException() { super(); }

	public PaillierContextMismatchException(String message) { super(message); }

	public PaillierContextMismatchException(Throwable cause) { super(cause); }

	public PaillierContextMismatchException(String message, Throwable cause) {
		super(message, cause);
	}

	public PaillierContextMismatchException(
		String message,
		Throwable cause,
		boolean enableSuppression,
		boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
