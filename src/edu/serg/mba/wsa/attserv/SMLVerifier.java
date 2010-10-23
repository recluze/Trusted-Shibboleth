/*
 * Copyright (C) 2008 Security Engineering Research Group, 
 * Institute of Management Sciences, Peshawar, Pakistan.
 * http://serg.imsciences.edu.pk 
 * authors: Nauman and Tamleek 
 */

package edu.serg.mba.wsa.attserv;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmCompositeHash;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrValue;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.impl.java.tsp.TcPcrCompositeBase;
import iaik.tc.tss.api.tspi.TcTssAbstractFactory;
import iaik.tc.tss.impl.java.tsp.TcTssLocalCallFactory;
import iaik.tc.utils.logging.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Arrays;
import java.util.StringTokenizer;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import edu.serg.mba.wsa.attserv.utils.XmlUtils;

public class SMLVerifier {
	private final Logger log = LoggerFactory.getLogger(PCRVerifier.class);

	public ResultType verify(Document src) {
		// extract the SML
		String sml;
		sml = XmlUtils.getNodeXPathOneString(src, "//smlcontents[1]/text()");

		log.debug(sml);

		// compute the final expected PCR 10 value
		// -------------------------------------------------------------------
		// Initial value of the PCR is set to 160-bits filled with 0s
		byte initVal[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
		TcBlobData hashVal = TcBlobData.newByteArray(initVal);
		StringTokenizer st = new StringTokenizer(sml);
		long smlVerifEnd;
		while (st.hasMoreTokens()) {
			// discard the first token
			st.nextToken();
			// save the second token in hasVal
			String filehash = st.nextToken();
			byte nextHash[] = XmlUtils.toBinArray(filehash);
			// log.debug(XmlUtil.toHexString(nextHash));
			TcBlobData nextHashBlob = TcBlobData.newByteArray(nextHash);

			hashVal.append(nextHashBlob);
			hashVal = hashVal.sha1();

			// save the third token in filehashed
			String filepath = st.nextToken();

			// check for file path against individual file hash
			ResultType fileHashResult = checkFileHash(filepath, filehash);
			// there can be three results:
			// 1. file hash is unknown ...
			// 2. file hash is known bad
			// 3. file hash is known good
			// we continue only if it's the last case. otherwise, return
			if (fileHashResult != ResultType.SML_VERIFICATION_SUCCESSFUL)
				return fileHashResult;
		}
		// here, all hashes are in a known good state. Let's see if they match
		// the PCR value returned to us
		// hashVal contains the final hash. let's get the compositeHash

		log.debug("Expected PCR value: "
				+ XmlUtils.toHexString(hashVal.asByteArray()));

		// first reteive the PCRCompositeHash sent from request
		String strPcrCompositeReceived = XmlUtils.getNodeXPathOneString(src,
				"//Data10[1]/text()").substring(16, 56);
		try {

			/*
			 * NOTE: I have received the same resulting hash from the manual
			 * calculating as the following automatic one. The problem is that
			 * hte result is not correct. This probably means that I don't
			 * understand the mechanism of creating pcrcomp structure
			 * properly... FIXED. No need for manual calculation. Got the
			 * mechanism working. Comments follow with code
			 */

			// TcIContext context = getTssFactory().newContextObject();
			//
			// creating PCR Composite hash
			TcTpmPcrValue tpmVal = new TcTpmPcrValue();
			tpmVal.setDigest(hashVal);
			// context.connect(null);
			TcTpmPcrSelection sel = new TcTpmPcrSelection();

			/*
			 * Although our TPM supports 24 PCRs, the `minimum' for SizeOfSelect
			 * is 2 bytes ... hence, two bytes and not three.
			 */
			byte[] selects = new byte[2];

			// select PCR 10 : Bit map: [00 00 01 00] [00 00 00 00]
			// see TPM Structures Spec: page 66-68:
			Arrays.fill(selects, (byte) 0);
			selects[1] = (byte) 0x04;
			sel.setPcrSelect(TcBlobData.newByteArray(selects));

			// create a PCR composite object
			TcTpmPcrComposite pcrComp = new TcTpmPcrComposite();
			pcrComp.setSelect(sel);
			// set the PCR value computed from SML
			TcTpmPcrValue[] tmp = new TcTpmPcrValue[1];
			tmp[0] = new TcTpmPcrValue(hashVal);
			pcrComp.setPcrValue(tmp);

			// compute the HASH of the pcrcomposite structure
			TcTpmCompositeHash pcrCompHash = new TcTpmCompositeHash(pcrComp
					.getEncoded().sha1());
			String strExpectedPcrComp = XmlUtils.toHexString(pcrCompHash
					.getEncoded().asByteArray());

			log.debug("PcrCompositeHashExpected : " + strExpectedPcrComp);
			log.debug("PcrCompositeHashReceived : " + strPcrCompositeReceived);
			// match pcrCompositeExpected against that sent to us
			if (strExpectedPcrComp.equals(strPcrCompositeReceived))
				return ResultType.SML_VERIFICATION_SUCCESSFUL;
			else
				return ResultType.SML_VERIFICATION_PCR_MISMATCH;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ResultType.SML_VERIFICATION_FAILED_UNKNOWN;
	}

	private ResultType checkFileHash(String filepath, String filehash) {
		boolean found = false;
		try {
			Statement stmt;

			// Register the JDBC driver for MySQL.
			Class.forName("com.mysql.jdbc.Driver");

			// Define URL of database server for
			// database named JunkDB on the localhost
			// with the default port number 3306.
			String url = "jdbc:mysql://localhost:3306/INTEGRITY";

			// Get a connection to the database for a
			// user named auser with the password
			// drowssap, which is password spelled
			// backwards.
			Connection con = DriverManager.getConnection(url, "root", "123456");

			// Display URL and connection information
			// log.debug("URL: " + url);
			// log.debug("Connection: " + con);

			// Get a Statement object
			stmt = con.createStatement();
			// database.
			// log.debug("Display all results:");

			String strQuery = "select * from KNOWN_GOOD where " + "hash='"
					+ filehash + "' and file='" + filepath + "';";

			ResultSet rs = stmt.executeQuery(strQuery);

			while (rs.next()) {
				// even if one found, it's known_good
				found = true;
			}
			con.close();
			con = null;

		} catch (Exception e) {
			log.debug(e.getMessage());
			log.debug("Error contacting mysql validation database at localhost");
			e.printStackTrace();
		}
		if (found) {
			log.debug("Good hash:" + filepath);
			return ResultType.SML_VERIFICATION_SUCCESSFUL;
		} else {
			log.debug("Unknown hash:" + filepath);
			return ResultType.SML_VERIFICATION_HASH_UNKNOWN;
		}
	}

	private TcTssAbstractFactory cachedFactory = null;

	public TcTssAbstractFactory getTssFactory() {
		// only create a new factory if no cache found
		if (cachedFactory == null) {
			try {
				// create a factory
				TcTssAbstractFactory factory = new TcTssLocalCallFactory();

				// get a context object
				TcIContext context = factory.newContextObject();

				// try to connect for testing
				// context.connect();
				// context.closeContext();

				// cache this factory
				cachedFactory = factory;
			} catch (TcTssException tse) {
				Log.err(tse.getMessage()); // use standard log
			}
		}
		return cachedFactory;
	}

}

// / to get sha-1
// input = a byte array
// byte[] digest = null;
// try {
// MessageDigest md = MessageDigest.getInstance("SHA-1");
// md.update(input);
// digest = md.digest();
// } catch (NoSuchAlgorithmException e) {
// // can be ignored since startup checks were OK
// }
