/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 */

package csrdu.mba.wsa.client.attestor;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.utils.logging.Log;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrComposite;

import iaik.tc.tss.impl.java.tsp.TcPcrCompositeInfoLong;

import java.io.File;
import java.util.StringTokenizer;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;

import csrdu.mba.wsa.util.CommonSettings;
import csrdu.mba.wsa.util.XmlUtil;

/**
 * Class to gather PCR values from the TPM through the TSS
 * 
 * @author <a href="http://recluze.wordpress.com">Nauman</a>
 * 
 */
public class SMLAttestor implements AbstractAttestor {
	// private String IMAPATH =
	// "/sys/kernel/security/ima/ascii_runtime_measurements";
	private String IMAPATH = "/sys/kernel/security/ima/ascii_runtime_measurements";

	/**
	 * The main function for handling SML requests.
	 * 
	 * @return XML Document containing the SML
	 * 
	 */
	@Override
	public Document process(byte nonce[]) {
		// create a document to hold the SML
		Document sml = null;
		try {
			sml = DocumentBuilderFactory.newInstance().newDocumentBuilder()
					.newDocument();
			sml.appendChild(sml.createElement("sml"));
		} catch (Exception e) {
			Log.err(e.getMessage());
			e.printStackTrace();
		}

		// read the contents of IMAPATH file

		/** ********************************************************** */
		/* SML Reading */
		String IMAPATH = "/sys/kernel/security/ima/ascii_runtime_measurements";
		// String IMAPATH = "C:\\Users\\Nauman\\Desktop\\ima.txt";
		File f = new File(IMAPATH);
		String contents = "";

		if (f.exists()) // check that the file exists
		{ // before trying to create a
			// BufferedReader
			// Create a BufferedReader from the file
			java.io.BufferedReader inFile = null;
			try {
				inFile = new java.io.BufferedReader(new java.io.FileReader(
						IMAPATH));
			} catch (Exception e) {
				e.printStackTrace();
			}
			// Compare the results of calling the readLine method to
			// null
			// to determine if you are at the end of the file.
			try {
				String line = inFile.readLine();
				while (line != null) {
					// System.out.println(++lineNum + ": " + line);
					// line = inFile.readLine();
					// System.out.println(line);
					contents += line;
					contents += " \n ";
					line = inFile.readLine();
				}
				// Close the buffered reader input stream attached to the
				// file
				inFile.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		// add the contents to the file
		XmlUtil.appendElement(sml, sml.getDocumentElement(), "smlcontents", contents);
		
		/*******************       Verification portion ******************/

		// Initial value of IMA is set to 160-bits filled with 0s
		byte initVal[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
		TcBlobData hashVal = TcBlobData.newByteArray(initVal);
		StringTokenizer st = new StringTokenizer(contents);
		long smlVerifStart = System.currentTimeMillis();
		long smlVerifEnd;
		while (st.hasMoreTokens()) {
			// discard the first token
			st.nextToken();
			// save the second token in hasVal
			byte nextHash[] = XmlUtil.toBinArray(st.nextToken());
			// System.out.println(XmlUtil.toHexString(nextHash));
			TcBlobData nextHashBlob = TcBlobData.newByteArray(nextHash);

			hashVal.append(nextHashBlob);
			hashVal = hashVal.sha1();

			// save the third token in filehashed
			String filehashed = st.nextToken();

			// check filehashed.HASH = hashVal through a database here
		}
		
		// hashVal contains the final hash. Now, let's printout the compositeHash
		try{
		TcIContext context = CommonSettings.getTssFactory()
		.newContextObject();
		
		context.connect(null);
		
		TcIPcrComposite pcrComp = context.createPcrCompositeObject(0);
		pcrComp.selectPcrIndex(10);
		pcrComp.setPcrValue(10, hashVal);
		
		System.out.println(pcrComp.getPcrValue(10).toHexStringNoWrap());
		
		// System.out.println("PCRComposite value: "  + pcrComp.g)
		System.out.println(XmlUtil.toHexString(pcrComp.getPcrCompositeHash().asByteArray()));
		context.closeContext();
		smlVerifEnd = System.currentTimeMillis();
		// System.out.println("SML Verification time: (in miliseconds) " + (smlVerifEnd - smlVerifStart));
		}catch (Exception e){
			e.printStackTrace();
		}
		
		// System.out.println(hashVal.toHexStringNoWrap());
		/*******************    end Verification portion ******************/
		

		// return the document
		return sml;
	}
}
