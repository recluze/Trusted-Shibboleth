/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 */

package csrdu.mba.wsa.client;

import iaik.tc.utils.logging.Log;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.*;
import org.w3c.dom.traversal.NodeIterator;
import org.xml.sax.InputSource;
import com.sun.org.apache.xpath.internal.CachedXPathAPI;

import csrdu.mba.wsa.client.attestor.*;
import csrdu.mba.wsa.util.*;

/**
 * Attestation Daemon processing attestation requests from local clients. Not
 * accessible directly from outside the client.
 * 
 * @author <a href="http://recluze.wordpress.com">Nauman</a>
 * 
 */
public class AttestationDaemon {
	/**
	 * The main function for handling attestation requests.
	 * 
	 * @param request
	 *            The XML request for attestation. Required to conform to
	 *            WS-Attestation standard
	 * 
	 */
	public Document doAttestation(Document request) {
		// create skeleton response
		Document returnedDoc = null;
		try {
			returnedDoc = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse(
							"/root/responseSkel.xml");

			// first retrieve the nonce
			String nonce = getNonce(request);
			byte nonceArray[] = XmlUtil.toBinArray(nonce);

			// enter the nonce in the response
			XmlUtil.appendElement(returnedDoc,
					getResponseMainNode(returnedDoc), "Challenge", nonce);

			// get the PCRs
			Document pcrs = (new PCRAttestor()).process(nonceArray);
			// add the PCRs to response
			XmlUtil.importName(pcrs, returnedDoc ,
					getResponseMainNode(returnedDoc));

			// get the SML
			Document sml = (new SMLAttestor()).process(nonceArray);
			// add the SML to response
			XmlUtil.importName(sml,returnedDoc ,
					getResponseMainNode(returnedDoc));

		} catch (Exception e) {
			e.printStackTrace();
		}
		return returnedDoc;
	}

	// 
	// public void importName(Document doc1,Document doc2) {
	// Element root1 = doc1.getDocumentElement();
	// Element personInDoc1 = (Element)root1.getFirstChild();
	//
	// Node importedPerson = doc2.importNode(personInDoc1,true);
	//
	// Element root2 = doc2.getDocumentElement();
	// root2.appendChild(importedPerson);
	// }

	private String getNonce(Document src) {
		try {
			String xpath = "//Challenge[1]/text()";

			// System.out.println("Querying Dom using : " + xpath);
			CachedXPathAPI path = new CachedXPathAPI();
			NodeIterator nl = path.selectNodeIterator(src, xpath);
			// the actual XPath selector

			Node n;
			if ((n = nl.nextNode()) != null) {
				return n.getNodeValue();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}

	private Node getResponseMainNode(Document src) {
		try {
			String xpath = "//RequestedSecurityToken[1]";

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
}
