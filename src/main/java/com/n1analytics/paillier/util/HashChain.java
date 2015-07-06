package com.n1analytics.paillier.util;

public class HashChain {
	private int hash;
	
	public HashChain() {
		this.hash = 0;
	}
	
	public HashChain chain(Object o) {
		this.hash = Long
			.valueOf((((long)this.hash) << 32) | o.hashCode())
			.hashCode();
		return this;
	}
	
	@Override
	public int hashCode() {
		return hash;
	}
	
	@Override
	public boolean equals(Object o) {
		return o == this || (
			o != null &&
			o instanceof HashChain &&
			hash == ((HashChain)o).hash);
	}
}
