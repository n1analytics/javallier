package com.n1analytics.paillier;

public class DecryptException extends PaillierRuntimeException {
	private static final long serialVersionUID = 264081054288775421L;

	public DecryptException() { super(); }

	public DecryptException(String message) { super(message); }

	public DecryptException(Throwable cause) { super(cause); }

	public DecryptException(String message, Throwable cause) {
		super(message, cause);
	}

	public DecryptException(
		String message,
		Throwable cause,
		boolean enableSuppression,
		boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
