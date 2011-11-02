/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 */

package csrdu.mba.wsa.client.attestor;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.structs.tsp.TcUuidFactory;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.utils.logging.Log;

import java.io.File;
import java.io.FileInputStream;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.NodeIterator;

import com.sun.org.apache.xpath.internal.CachedXPathAPI;

import csrdu.mba.wsa.util.CommonSettings;

import csrdu.mba.wsa.util.XmlUtil;

/**
 * Class to gather PCR values from the TPM through the TSS
 * 
 * @author <a href="http://recluze.wordpress.com">Nauman</a>
 * 
 */
public class PCRAttestor implements AbstractAttestor {
	// private String BACLIENT_AIK_KEY = "baclientaik";
	private String BACLIENT_AIK_SECRET = "secret";

	// created AIK with command
	// "aik_create -a baclientaiksecret -l baclientaik -o alijan "
	// SRK is set to TSS_WELL_KNOWN_SECRET

	private String AIK_FILENAME = "/root/tpm-softs/trustjava/jTpmTools_0.3a/bac_aik.tpmkey";

	// // statically assigning the UUID of the AIK above here:
	// // FIXME: Can this be done dynamically through AIK Label?
	// // QUESTION: Does this change with restart? Are there any other problems?
	// String baclientUUID = "00000001-0002-0003-0405-6576352a7d41";

	/**
	 * The main function for handling PCR requests. *
	 * 
	 * @param nonce
	 *            The 20-Byte nonce to pass to the TPM for inclusion in
	 *            TSS_VALIDATION structure.
	 * @return XML Document containing the PCRs
	 */
	@Override
	public Document process(byte nonce[]) {
		// FIXME: Change byte[] to String
		// build a document to store the results
		Document pcrs = null;
		try {
			pcrs = DocumentBuilderFactory.newInstance().newDocumentBuilder()
					.newDocument();
			pcrs.appendChild(pcrs.createElement("pcrvals"));
		} catch (Exception e) {
			Log.err(e.getMessage());
			e.printStackTrace();
		}

		// *********************************************************
		// get the PCR values
		// *********************************************************
		long getPcrStart = System.currentTimeMillis();
		long getPcrEnd;

		try {
			// create a context for TSS
			TcIContext context = CommonSettings.getTssFactory()
					.newContextObject();

			context.connect(null); // connect to localhost
			TcITpm tpm = context.getTpmObject();

			// get the number of PCRs from TPM
			TcBlobData subCap = TcBlobData
					.newUINT32((int) TcTssConstants.TSS_TPMCAP_PROP_PCR);
			long numPCRs = tpm.getCapabilityUINT32(
					TcTssConstants.TSS_TPMCAP_PROPERTY, subCap);
			
			System.out.println("Number of PCRs = " + numPCRs);

			for (int i = 10; i < 11; i++) { // only check first 10 pcrs for the
				// time being
				// create a pcr composite object
				TcIPcrComposite pcrComp = context.createPcrCompositeObject(0);
				pcrComp.selectPcrIndex(i);

				// set pcr value to read
				pcrComp.setPcrValue(i, tpm.pcrRead(i));

				// create an aik key object to load ... use BACLIENT_AIK_KEY as
				// label of the AIK to quote with

				// first loading the SRK
				TcBlobData srkSecret = TcBlobData
						.newByteArray(TcTssConstants.TSS_WELL_KNOWN_SECRET);
				long srkSecretMode = TcTssConstants.TSS_SECRET_MODE_SHA1;

				// create the UUID of the AIK: FIXED: don't need it
				// TcTssUuid uuid = new TcTssUuid().initString(baclientUUID);

				// set the key password // try ASCII if this doesn't work
				TcBlobData keySecret = TcBlobData.newString(
						BACLIENT_AIK_SECRET, false, "UTF-16LE");

				// load the SRK
				TcIRsaKey srk = context.loadKeyByUuidFromSystem(TcUuidFactory
						.getInstance().getUuidSRK());

				// TcIPolicy srkPolicy = context
				// .createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
				TcIPolicy srkPolicy = srk.getUsagePolicyObject();
				srkPolicy.setSecret(srkSecretMode, srkSecret);
				srkPolicy.assignToObject(srk);

				// the AIK
				// TcIRsaKey identityKey = context.getKeyByUuid(
				// TcTssConstants.TSS_PS_TYPE_SYSTEM, uuid);

				// load key from system to a byte array
				byte blob[] = null;
				try {
					File f = new File(AIK_FILENAME);
					blob = new byte[(int) f.length()];
					FileInputStream fi = new FileInputStream(f);
					fi.read(blob);
				} catch (Exception e) {
					e.printStackTrace();
				}

				// create a TcBlobData using
				TcBlobData keyBlob = TcBlobData.newByteArray(blob);

				// load the key using this blob
				TcIRsaKey identityKey = context.loadKeyByBlob(srk, keyBlob);

				// TcIPolicy keyUsgPolicy = context
				// .createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
				TcIPolicy keyUsgPolicy = identityKey.getUsagePolicyObject();
				keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
						keySecret);
				keyUsgPolicy.assignToObject(identityKey);
				identityKey.loadKey(srk);

				// create a TCBlobData using the provided nonce
				TcBlobData nonceData = TcBlobData.newByteArray(nonce);
				TcTssValidation nonceVal = new TcTssValidation();
				nonceVal.setExternalData(nonceData);

				// the tpmQuote to receive data from tpm's quote
				TcTssValidation tpmQuote = new TcTssValidation();

				// now get the quote
				tpmQuote = tpm.quote(identityKey, pcrComp, nonceVal);

				// output unsigned value
				// first output the container
				XmlUtil.appendElement(pcrs, pcrs.getDocumentElement(), "pcrs",
						"");

				// append the number of the PCR
				XmlUtil.appendElement(pcrs, getPCRContainer(pcrs), "num",
						Integer.toString(i));

				// append the validation structure to the doc
				XmlUtil.appendElement(pcrs, getPCRContainer(pcrs),
						"ValStructure" + i, XmlUtil.toHexString(tpmQuote
								.getValidationData().asByteArray()));

				// append the data
				XmlUtil.appendElement(pcrs, getPCRContainer(pcrs), "Data" + i,
						XmlUtil.toHexString(tpmQuote.getData().asByteArray()));

				getPcrEnd = System.currentTimeMillis();

				// System.out.println("PCR measurement and Signing: (in
				// miliseconds) " + (getPcrEnd - getPcrStart));

				// output signed value
				// XmlUtil.appendElement(pcrs, pcrs.getDocumentElement(),
				// "pcrSigned" + i, pcrComp.getPcrValue(i)
				// .toHexStringNoWrap());

				// XmlUtil.appendElement(pcrs, pcrs.getDocumentElement(),
				// "pcrSigned" + i, tpmQuote.getValidationData()
				// .toHexStringNoWrap());

				/*
				 * IMPORTANT: The tpmQuote.getExternalData() contains only the
				 * nonce
				 */
				// TcIRsaKey pubAik = identityKey;
				// TcBlobData pubAikBlob = pubAik.getAttribData(
				// TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
				// TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
				//
				// TcTpmPubkey pubAikStruct = new TcTpmPubkey(pubAikBlob);
				//
				// TcBlobData computedPCRs =
				// TcBlobData.newBlobData(tpm.pcrRead(i)
				// .sha1());
				// // PCR_Extend works like this:
				// // newPcrContent = oldPcrContent.append(data.sha1());
				// computedPCRs.append(nonceData);
				//
				// // System.out.println("tpm.pcrRead:"
				// // + tpm.pcrRead(i).toHexStringNoWrap());
				// // System.out.println("tpmQuote.ValData:"
				// // + tpmQuote.getValidationData().toHexStringNoWrap());
				// // System.out.println("tpmQuote.Data:"
				// // + tpmQuote.getData().toHexStringNoWrap());
				// // System.out.println("tpmQuote.ExternalData:"
				// // + tpmQuote.getExternalData().toHexStringNoWrap());
				// // System.out.println("tpmQuote.Data.sha1:"
				// // + tpmQuote.getData().sha1().toHexStringNoWrap());
				// // System.out.println("computedPcrs:"
				// // + computedPCRs.toHexStringNoWrap());
				// // System.out.println("CompositeHash:"
				// // + pcrComp.getPcrCompositeHash().toHexStringNoWrap());
				// // System.out.println("nonceVal.ValData:"
				// // + nonceVal.getValidationData().toHexStringNoWrap());
				// // System.out.println("nonceVal.Data:"
				// // + nonceVal.getData().toHexStringNoWrap());
				// // System.out.println("nonceVal.ExternalData:"
				// // + nonceVal.getExternalData().toHexStringNoWrap());
				//
				// BouncyCastleProvider bcp = new BouncyCastleProvider();
				// java.security.Security.addProvider(bcp);
				//
				// Cipher cipher = Cipher.getInstance("RSA/None/NoPadding",
				// bcp);
				//
				// // cipher.init(Cipher.ENCRYPT_MODE, TcCrypto
				// // .pubTpmKeyToJava(pubAikStruct));
				// cipher.init(Cipher.ENCRYPT_MODE, TcCrypto
				// .pubTpmKeyToJava(pubAikStruct));
				//
				// // byte[] cipherText =
				// // cipher.doFinal(tpmQuote.getValidationData()
				// // .asByteArray());
				// byte[] cipherText =
				// cipher.doFinal(tpmQuote.getData().getRange(
				// 0, 28));
				// // System.out.println("cipher: "
				// // + TcBlobData.newByteArray(cipherText)
				// // .toHexStringNoWrap());
				//
				// verify(tpmQuote.getValidationData().asByteArray(), TcCrypto
				// .pubTpmKeyToJava(pubAikStruct), tpmQuote.getData()
				// .asByteArray());
				context.closeContext();

			}
		} catch (TcTssException tse) {
			Log.err(tse.getMessage());
			tse.printStackTrace();
		} catch (Exception nse) {
			nse.printStackTrace();
		}
		return pcrs;
	}

	private Node getPCRContainer(Document src) {
		try {
			String xpath = "//pcrs[1]";

			CachedXPathAPI path = new CachedXPathAPI();
			NodeIterator nl = path.selectNodeIterator(src, xpath);
			// the actual XPath selector)
			Node n;
			if ((n = nl.nextNode()) != null) {
				return n;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public void verify(byte[] signedPcrVal, RSAPublicKey pubKey, byte[] pcrVal) {

		// read key directly from file
		try {
			// FileInputStream keyfis = new FileInputStream(AIK_FILENAME);
			// byte[] encKey = new byte[keyfis.available()];
			// keyfis.read(encKey);
			//
			// keyfis.close();
			//
			// X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
			// KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SUN");
			// PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
			long valPcrStart = System.currentTimeMillis();
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(pubKey);
			sig.update(pcrVal);

			boolean verifies = sig.verify(signedPcrVal);
			long valPcrEnd = System.currentTimeMillis();
			System.out.println("Pcr Validation Time:"
					+ (valPcrEnd - valPcrStart));
			// System.out.println(verifies);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

// TcITpmPcrInfo pcrInfo = null;
// if (pcrComposite != null) {
// if (pcrComposite instanceof TcPcrCompositeInfoLong) {
// pcrInfo = new TcTpmPcrInfoLong(((TcPcrCompositeBase)
// pcrComposite).getPcrStructEncoded());
// } else if (pcrComposite instanceof TcPcrCompositeInfo) {
// pcrInfo = new TcTpmPcrInfo(((TcPcrCompositeBase)
// pcrComposite).getPcrStructEncoded());
// } else {
// throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
// "PCR structure has to be of type PcrInfo or PcrInfoLong.");
// }
// }

// import javax.crypto.Cipher;
//
// /**
// * Basic RSA example.
// */
// public class BaseRSAExample
// {
// public static void main(String[] args) throws Exception
// {
// byte[] input = new byte[] { (byte)0xbe, (byte)0xef };
// Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
//
// // create the keys
// KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
//
// RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
// new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
// new BigInteger("11", 16));
// RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
// new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
// new BigInteger("57791d5430d593164082036ad8b29fb1", 16));
//
// RSAPublicKey pubKey = (RSAPublicKey)keyFactory.generatePublic(pubKeySpec);
// RSAPrivateKey privKey = (RSAPrivateKey)keyFactory.generatePrivate(
// privKeySpec);
//
// System.out.println("input : " + Utils.toHex(input));
//
// // encryption step
//
// cipher.init(Cipher.ENCRYPT_MODE, pubKey);
//
// byte[] cipherText = cipher.doFinal(input);

