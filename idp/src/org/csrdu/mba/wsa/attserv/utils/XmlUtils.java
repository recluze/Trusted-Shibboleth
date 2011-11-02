/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 * Derived from iaik.tc.apps.jtt.common.CommonSettings of jTpmTools from iaik 
 */

package org.csrdu.mba.wsa.attserv.utils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.NodeIterator;

import com.sun.org.apache.xpath.internal.CachedXPathAPI;

import java.math.BigInteger;

/**
 * Utility class for xml related common functions
 * 
 * @author <a href="http://recluze.wordpress.com">Nauman</a>
 * 
 */
public class XmlUtils {
	/**
	 * Extend an XML document "doc" by appending an element "name" with value
	 * "val" to the end of the node "to"
	 * 
	 * @param doc
	 *            Document to add the element to
	 * @param to
	 *            The node where the new element should be appended
	 * @param name
	 *            Name of the element to add
	 * @param val
	 *            Value within the new node
	 * 
	 */
	static char[] hexChar = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'A', 'B', 'C', 'D', 'E', 'F' };

	public static void appendElement(Document doc, Node to, String name,
			String val) {
		Element newEl = doc.createElement(name); // new Element
		Node newElVal = doc.createTextNode(val); // new value
		newEl.appendChild(newElVal);
		to.appendChild(newEl);
	}

	/**
	 * Function for importing a document's root element (doc1) into another
	 * (doc2) Thanks to: http://www.java2s.com/Code/Java/XML/
	 * JavaDOMeditCopyaNodefromOneParseTreeintoAnother.htm
	 * 
	 * 
	 * @param doc1
	 *            Document to add the element to
	 * @param doc2
	 *            The node where the new element should be appended
	 * @param which
	 *            Which node of doc2 to add doc1 to
	 * 
	 */

	public static void importName(Document doc1, Document doc2, Node which) {
		Element root1 = doc1.getDocumentElement();
		// Element personInDoc1 = (Element) root1.getFirstChild();
		Node personInDoc1 = root1.getFirstChild();
		Node importedPerson = doc2.importNode(personInDoc1, true);

		Node root2 = which;
		root2.appendChild(importedPerson);
	}

	/**
	 * Convert a byte array to string representation of the array: Source:
	 * http://forum.java.sun.com/thread.jspa?threadID=659432&messageID=3873051
	 * 
	 * @param b
	 *            The byte array to convert
	 * @return the string representing the byte array
	 * 
	 */
	public static String toHexString(byte[] b) {
		StringBuffer sb = new StringBuffer(b.length * 2);
		for (int i = 0; i < b.length; i++) {
			// look up high nibble char
			sb.append(hexChar[(b[i] & 0xf0) >>> 4]); // fill left with zero
			// bits

			// look up low nibble char
			sb.append(hexChar[b[i] & 0x0f]);
		}
		return sb.toString();
	}

	/**
	 * Convert a string representation of a byte array to byte[]: Source:
	 * http://forum.java.sun.com/thread.jspa?threadID=659432&messageID=3873051
	 * 
	 * @param hexStr
	 *            The string to convert
	 * @return the byte array represented by the string
	 * 
	 */

	public static byte[] toBinArray(String hexStr) {
		byte bArray[] = new byte[hexStr.length() / 2];
		for (int i = 0; i < (hexStr.length() / 2); i++) {
			byte firstNibble = Byte.parseByte(hexStr
					.substring(2 * i, 2 * i + 1), 16); // [x,y)
			byte secondNibble = Byte.parseByte(hexStr.substring(2 * i + 1,
					2 * i + 2), 16);
			int finalByte = (secondNibble) | (firstNibble << 4); //bit-operations
			// only with
			// numbers,
			// not
			// bytes.
			bArray[i] = (byte) finalByte;
		}
		return bArray;
	}

	public static NodeIterator getNodeXPath(Document src, String node) {
		try {
			String xpath = node;

			CachedXPathAPI path = new CachedXPathAPI();
			NodeIterator nl = path.selectNodeIterator(src, xpath);
			// the actual XPath selector)
			return nl;
			// Node n;
			// if ((n = nl.nextNode()) != null) {
			// return n;
			// }
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;

	}

	public static String getNodeXPathOneString(Document src, String node) {
		try {
			String xpath = node;

			CachedXPathAPI path = new CachedXPathAPI();
			NodeIterator nl = path.selectNodeIterator(src, xpath);
			// the actual XPath selector)

			Node n;
			if ((n = nl.nextNode()) != null) {
				// System.out.println(n.getNodeValue());
				return n.getNodeValue();
			} else {
				System.out.println("node not found: " + node);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Exception in extraction: " + node);
		}
		return null;

	}
}
