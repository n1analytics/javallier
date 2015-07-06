package com.n1analytics.paillier;

public class PaillierKeyMismatchException extends PaillierRuntimeException {
	private static final long serialVersionUID = -1454035978739577475L;

	public PaillierKeyMismatchException() { super(); }

	public PaillierKeyMismatchException(String message) { super(message); }

	public PaillierKeyMismatchException(Throwable cause) { super(cause); }

	public PaillierKeyMismatchException(String message, Throwable cause) {
		super(message, cause);
	}

	public PaillierKeyMismatchException(
		String message,
		Throwable cause,
		boolean enableSuppression,
		boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
