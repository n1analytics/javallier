package com.n1analytics.paillier;

public class EncryptException extends PaillierRuntimeException {
	private static final long serialVersionUID = -5497548195268474994L;

	public EncryptException() { super(); }

	public EncryptException(String message) { super(message); }

	public EncryptException(Throwable cause) { super(cause); }

	public EncryptException(String message, Throwable cause) {
		super(message, cause);
	}

	public EncryptException(
		String message,
		Throwable cause,
		boolean enableSuppression,
		boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
