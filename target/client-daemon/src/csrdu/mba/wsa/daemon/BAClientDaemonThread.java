/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 */


package csrdu.mba.wsa.daemon;

import java.net.*;
import java.io.*;

import csrdu.mba.wsa.client.*;

import org.xml.sax.InputSource;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class BAClientDaemonThread extends Thread {
	private Socket socket = null;

	public BAClientDaemonThread(Socket socket) {
		super("BAClientDaemonThread");
		this.socket = socket;
	}

	public void run() {

		try {
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			InputStreamReader sreader = new InputStreamReader(socket
					.getInputStream());
			BufferedReader in = new BufferedReader(sreader);

			String inputXML = "", outputXML = "";
			String temp;
			temp = in.readLine();
			while (!temp.equals("bye")) {
				// System.out.println("::" + temp + "::");
				inputXML += temp;
				temp = in.readLine();
			}

			System.out.println(inputXML);
			StringReader sr1 = new StringReader(inputXML);
			InputSource is = new InputSource(sr1);
			// Document request = DocumentBuilderFactory.newInstance()
			// .newDocumentBuilder().parse(socket.getInputStream());

			Document request = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse(is);

			AttestationDaemon ad = new AttestationDaemon();
			Document response = ad.doAttestation(request);
			// response = request;

			String strRes = "";
			// convert request XML to string
			TransformerFactory tFactory = TransformerFactory.newInstance();
			Transformer transformer = tFactory.newTransformer();

			DOMSource source = new DOMSource(response);
			StringWriter sw = new StringWriter();
			StreamResult result = new StreamResult(sw);
			transformer.transform(source, result);
			strRes = sw.toString();

			// System.out.println(strReq);
			out.println(strRes);
			out.println("bye");
			out.flush();

			out.close();
			// in.close();
			socket.close();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
