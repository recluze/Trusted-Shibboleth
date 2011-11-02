/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 */

package csrdu.mba.wsa.client.attestor;

import org.w3c.dom.Document;

/**
 * Attestor Interface. Defines only one function process which performs
 * attestation
 * 
 * @author <a href="http://recluze.wordpress.com">Nauman</a>
 * 
 */
public interface AbstractAttestor {
	/**
	 * The main function for handling attestation requests.
	 * 
	 * @param nonce
	 *            The 20-Byte nonce to pass to the TPM for inclusion in
	 *            TSS_VALIDATION structure.
	 * @return XML Document containing the required token
	 * 
	 */
	public Document process(byte[] nonce);
}
