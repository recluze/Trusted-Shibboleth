/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 */

package csrdu.mba.wsa.client;

import iaik.tc.utils.logging.Log;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import csrdu.mba.wsa.client.attestor.*;
import csrdu.mba.wsa.util.*;

/**
 * @author <a href="http://recluze.wordpress.com">Nauman</a>
 * 
 */

public class MainClient {

	/**
	 * Client for testing functionality of the client daemon
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		// long totStart = System.currentTimeMillis();
		// long totEnd;
		// /* create a dummy nonce */
		// byte nonce[] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5,
		// 0x1,
		// 0x2, 0x3, 0x4, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5 };

		// FIXME: convert nonce to string
		// &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
		// aurabh Arora wrote:
		// > how can i convert a 160 bit string nonce to TcBlobData type in
		// > jTSSWrapper library ?
		// >
		// > i hv tried :
		// > initString* functions, and get the "nullpointer exception" error.
		//
		// Looking at the Javadoc:
		// http://trustedjava.sourceforge.net/jtss/javadoc_tsp/iaik/tc/tss/api/structs/common/TcBlobData.html
		//
		// There is only one method starting with "initString*", that is
		// "initStringASCII".
		// As guessable from the name, it expects a String containing only ASCII
		// chars.
		//
		// If you want to pass in a 160bit nonce binary blob the "newByteArray"
		// method
		// may be your choice?
		// &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&

		// // call the attestors
		// PCRAttestor p = new PCRAttestor();
		// Document d = p.process(nonce);
		//
		// SMLAttestor p2 = new SMLAttestor();
		// Document d2 = p2.process(nonce);
		// //
		// // // output the new file
		// try {
		// DOMSource src = new DOMSource(d2);
		// StreamResult sr = new StreamResult(System.out);
		// TransformerFactory tf = TransformerFactory.newInstance();
		// Transformer t = tf.newTransformer();
		//
		// t.transform(src, sr);
		// } catch (Exception e) {
		// e.printStackTrace();
		// }
		//
		// try {
		// DOMSource src = new DOMSource(d);
		// StreamResult sr = new StreamResult(System.out);
		// TransformerFactory tf = TransformerFactory.newInstance();
		// Transformer t = tf.newTransformer();
		//
		// t.transform(src, sr);
		// } catch (Exception e) {
		// e.printStackTrace();
		// }
		//		
		// totEnd = System.currentTimeMillis();
		// System.out.println("tot Time taken: (in miliseconds) " + (totEnd -
		// totStart));
		try {
			Document request = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse("samplerequest.xml");
			Document response = (new AttestationDaemon())
					.doAttestation(request);

			DOMSource src = new DOMSource(response);
			StreamResult sr = new StreamResult(System.out);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer t = tf.newTransformer();
			t.transform(src, sr);

		} catch (Exception e) {
		}
	}
}
