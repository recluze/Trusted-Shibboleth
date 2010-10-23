/*
 * Copyright (C) 2008 Security Engineering Research Group, 
 * Institute of Management Sciences, Peshawar, Pakistan.
 * http://serg.imsciences.edu.pk 
 * authors: Nauman and Tamleek 
 */

package edu.serg.mba.wsa.attserv;

import java.io.*;
import java.net.*;

import javax.xml.transform.Transformer;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.parsers.DocumentBuilderFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import edu.serg.mba.wsa.attserv.utils.*;

public class Client {

	private final Logger log = LoggerFactory.getLogger(Client.class);

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// Client c = new Client();
		// c.attestClient("192.168.10.85");
	}

	public int remotePort = 8020; // just a random port for now

	public boolean attestClient(String targetAddr)
			throws AttestationDaemonConnectException {
		boolean AttestationResult = false; // the cumulative attestation result
		long timeStart = System.currentTimeMillis();

		Socket kkSocket = null;
		PrintWriter out = null;
		BufferedReader in = null;

		try {
			log.debug("Creating connection to target on port {}", remotePort);
			kkSocket = new Socket(targetAddr, remotePort);
			out = new PrintWriter(kkSocket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(kkSocket
					.getInputStream()));
		} catch (UnknownHostException e) {
			log.error("Don't know about host.");
			// System.exit(1);
			throw new AttestationDaemonConnectException();
		} catch (IOException e) {
			log.error("Couldn't get I/O for the connection to: " + targetAddr);
			throw new AttestationDaemonConnectException();
			// System.exit(1);
		} catch (Exception e){
			log.error(e.getMessage());
			throw new AttestationDaemonConnectException();
		}

		try {
			// read the request document .. should be created dynamicall
			// DONE: create request dynamically to incorporate NONCE
			Document request = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse("/root/samplerequest.xml");
			// this nonce would also become dynamic. FIXED
			// generate a 160-bit random nonce
			String nonce = generateNonce();

			// change the nonce
			putNonce(request, nonce);
			// send the request -------------------------------------------
			String strReq = "";
			// convert request XML to string
			TransformerFactory tFactory = TransformerFactory.newInstance();
			Transformer transformer = tFactory.newTransformer();

			DOMSource source = new DOMSource(request);
			StringWriter sw = new StringWriter();
			StreamResult result = new StreamResult(sw);
			transformer.transform(source, result);
			strReq = sw.toString();

			// log.debug(strReq);
			out.println(strReq);
			out.println("bye");
			out.flush();

			// get the response ----------------------------------
			String inputXML = "";
			String temp;
			temp = in.readLine();
			while (!temp.equals("bye")) {
				// tamper with the result to test the response
				// temp = temp.replace('3', '1');
				// end tamper
				inputXML += temp;
				temp = in.readLine();
			}

			// log.debug(inputXML);
			StringReader sr1 = new StringReader(inputXML);
			InputSource is = new InputSource(sr1);
			// Document request = DocumentBuilderFactory.newInstance()
			// .newDocumentBuilder().parse(socket.getInputStream());

			Document response = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse(is);

			// no need to: output the response
			// TODO: remove later (comment out later)
			DOMSource src2 = new DOMSource(response);
			StreamResult sr2 = new StreamResult(System.out);
			TransformerFactory tf2 = TransformerFactory.newInstance();
			Transformer t2 = tf2.newTransformer();
			t2.setOutputProperty(OutputKeys.INDENT, "yes");
			t2.transform(src2, sr2);
			// log.debug();

			out.close();
			in.close();
			kkSocket.close();

			// verification portion: *****************************************

			// verify the PCR ------------------------------------------------
			PCRVerifier pv = new PCRVerifier();
			ResultType pcrResult = pv.verify(response);
			if (pcrResult == ResultType.VERIFICATION_FAILED_NO_PCRS)
				log.debug("! --------------- No PCRS found in response.");
			else if (pcrResult == ResultType.VERIFICATION_FAILED_PCR_MISMATCH)
				log.debug("! --------------- PCRs Verification failed. ");
			if (pcrResult == ResultType.VERIFICATION_SUCCESSFUL) {
				log.debug("* --------------- PCRs signatures verified.");
				AttestationResult = true;
			}

			// now, since the quote can be trusted, we can verify the nonce
			//------------------------------------------------------------------
			// ----
			if (AttestationResult) {
				NonceVerifier nv = new NonceVerifier();
				ResultType nonceResult = nv.verify(response, nonce);
				if (nonceResult == ResultType.NONCE_MISMATCH) {
					AttestationResult = false;
					log.debug("! --------------- Nonce is stale. Verfication failed. ");
				} else if (nonceResult == ResultType.NONCE_MATCH_SUCCESSFUL) {
					AttestationResult = true;
					log.debug("* --------------- Nonce is correct and fresh. Verification Successful.");
				}
			}

			// finally do the SoftwareIntegrity portion...
			// i.e. SML verification -------------------------------------------
			if (AttestationResult) {
				SMLVerifier sv = new SMLVerifier();
				ResultType svResult = sv.verify(response);
				if (svResult == ResultType.SML_VERIFICATION_HASH_UNKNOWN) {
					AttestationResult = false;
					log
							.info("! --------------- Unknown hash found. Verification Failed.");
				} else if (svResult == ResultType.SML_VERIFICATION_VULNERABILITY) {
					AttestationResult = false;
					log
							.info("! --------------- A vulnerability found. Verification Failed.");
				} else if (svResult == ResultType.SML_VERIFICATION_PCR_MISMATCH) {
					AttestationResult = false;
					log
							.info("! --------------- Expected PCR does not match quoted PCR. Verification Failed.");
				} else if (svResult == ResultType.SML_VERIFICATION_SUCCESSFUL) {
					log.info("* --------------- SML Verification successful.");
				}
			}
		} catch (Exception e) {
			log.error(e.getMessage());
			e.printStackTrace();
		}

		long timeEnd = System.currentTimeMillis();
		log.debug("Time Taken (ms):" + (timeEnd - timeStart));
		return AttestationResult;
		// return false;
	}

	private void putNonce(Document src, String nonce) {
		// retrieve the Challenge node
		try {
			Node nonceNode = XmlUtils
					.getNodeXPath(src, "//Challenge[1]/text()").nextNode();
			// log.debug(nonceNode.getNodeValue());
			nonceNode.setNodeValue(nonce);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private String generateNonce() {
		char[] hexChar = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'A', 'B', 'C', 'D', 'E', 'F' };

		// geneate a new random Challenge
		String nonce = "";
		for (int i = 0; i < 20 * 2; i++) {
			// compute a nible each time and append to nonce
			Double rnd = Math.random() * 15;
			nonce += hexChar[rnd.intValue()];
		}
		// log.debug("New nonce: " + nonce);
		return nonce;
	}
}
