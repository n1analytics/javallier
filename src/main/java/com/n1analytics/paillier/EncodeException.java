package com.n1analytics.paillier;

public class EncodeException extends PaillierRuntimeException {
	private static final long serialVersionUID = -8363238490528476897L;

	public EncodeException() { super(); }

	public EncodeException(String message) { super(message); }

	public EncodeException(Throwable cause) { super(cause); }

	public EncodeException(String message, Throwable cause) {
		super(message, cause);
	}

	public EncodeException(
		String message,
		Throwable cause,
		boolean enableSuppression,
		boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
