/*
 * Copyright (C) 2008 Security Engineering Research Group, 
 * Institute of Management Sciences, Peshawar, Pakistan.
 * http://serg.imsciences.edu.pk 
 * authors: Nauman and Tamleek 
 */

package edu.serg.mba.wsa.attserv;

import java.io.File;
import java.io.FileInputStream;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.structs.tsp.TcUuidFactory;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.utils.logging.Log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.w3c.dom.traversal.NodeIterator;

import edu.serg.mba.wsa.attserv.utils.*;
import edu.serg.tshib.IntegrityProviderDataConnector;

public class PCRVerifier {
	private final Logger log = LoggerFactory.getLogger(PCRVerifier.class);

	public ResultType verify(Document src) {
		// get the <pcrs> node from the document

		NodeIterator pcrsNode = XmlUtils.getNodeXPath(src, "//pcrs[1]");

		int i = 10;
		Node n = null;
		if ((n = pcrsNode.nextNode()) == null)
			return ResultType.VERIFICATION_FAILED_NO_PCRS;

		// pcrs present. Now try reading each pcr to verify the signature

		// get the public key for signature verification
		RSAPublicKey pubKey = getRSAPubKey();
		// if no pcr values to verify, fail
		boolean finalRes = false;
		// first read the pub key from file
		do {
			// verify valStructure against data ---------------------
			// get the ValStructure
			String ValStruct;
			ValStruct = XmlUtils.getNodeXPathOneString(src,
					"//ValStructure10[1]/text()");
			// get the Data
			String Data;
			Data = XmlUtils.getNodeXPathOneString(src, "//Data10[1]/text()");

			// System.out.println(Data);
			// verify the signature
			finalRes = verifyValStruct(XmlUtils.toBinArray(ValStruct), pubKey,
					XmlUtils.toBinArray(Data));

		} while (((n = pcrsNode.nextNode()) != null) && finalRes);
		// exit if any of the verification fails

		if (!finalRes)
			return ResultType.VERIFICATION_FAILED_PCR_MISMATCH;
		else{
			log.debug("PCR verification successful");
			return ResultType.VERIFICATION_SUCCESSFUL;
		}
		
	}

	public boolean verifyValStruct(byte[] signedPcrVal, RSAPublicKey pubKey,
			byte[] pcrVal) {
		try {
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(pubKey);
			sig.update(pcrVal);
			boolean verifies = sig.verify(signedPcrVal);
			return verifies;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public RSAPublicKey getRSAPubKey() {
		final String pubAikFilename = "/root/bac_aik_pub.key";
		// first get the pubAikBlob from file (received from the target earlier)
		byte pubAik[] = null;
		try {
			File f = new File(pubAikFilename);
			pubAik = new byte[(int) f.length()];
			FileInputStream fi = new FileInputStream(f);
			fi.read(pubAik);
			TcBlobData pubAikBlob = TcBlobData.newByteArray(pubAik);
			// the following two lines should be performed on the challenger
			// side
			// to get the rsa public key for verification
			TcTpmPubkey pubAikStruct = new TcTpmPubkey(pubAikBlob);
			RSAPublicKey rsaPub = TcCrypto.pubTpmKeyToJava(pubAikStruct);
			return rsaPub;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
