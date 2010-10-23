/*
 * Copyright (C) 2008 Security Engineering Research Group, 
 * Institute of Management Sciences, Peshawar, Pakistan.
 * http://serg.imsciences.edu.pk 
 * authors: Nauman and Tamleek 
 */

package edu.serg.mba.wsa.attserv;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import edu.serg.mba.wsa.attserv.utils.XmlUtils;
import edu.serg.tshib.IntegrityProviderDataConnector;

public class NonceVerifier {
	private final Logger log = LoggerFactory.getLogger(NonceVerifier.class);

	public ResultType verify(Document src, String NonceSent) {
		boolean finalRes = false; // if no nonce, it fails
		String nonceReceived = XmlUtils.getNodeXPathOneString(src,
				"//Challenge[1]/text()");
		log.debug("Nonce Received: " + nonceReceived);
		log.debug("Nonce Sent: " + NonceSent);
		if (nonceReceived.equals(NonceSent))
			finalRes = true;

		// static nonce good... now verify against TPM signed nonce in DATA
		if (finalRes) {
			String Data;
			Data = XmlUtils.getNodeXPathOneString(src, "//Data10[1]/text()");

			String dataNonce = Data.substring(56, 96);
			log.debug("Data nonce: " + dataNonce);
			finalRes = dataNonce.equals(NonceSent);
		}
		if (finalRes)
			return ResultType.NONCE_MATCH_SUCCESSFUL;
		else
			return ResultType.NONCE_MISMATCH;
	}
}
