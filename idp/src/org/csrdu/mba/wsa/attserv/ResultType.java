/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 */

package org.csrdu.mba.wsa.attserv;

public enum ResultType {
	VERIFICATION_SUCCESSFUL, VERIFICATION_FAILED_NONCE, VERIFICATION_FAILED_PCR_MISMATCH, VERIFICATION_FAILED_UNKNOWN, VERIFICATION_FAILED_NO_PCRS, NONCE_MISMATCH, NONCE_MATCH_SUCCESSFUL, SML_VERIFICATION_SUCCESSFUL, SML_VERIFICATION_PCR_MISMATCH, SML_VERIFICATION_VULNERABILITY, SML_VERIFICATION_HASH_UNKNOWN, SML_VERIFICATION_FAILED_UNKNOWN
}
