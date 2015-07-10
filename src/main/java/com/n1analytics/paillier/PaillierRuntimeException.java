/**
 * Copyright 2015 NICTA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
