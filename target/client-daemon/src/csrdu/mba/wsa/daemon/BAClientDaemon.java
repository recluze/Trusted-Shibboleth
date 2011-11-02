/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 */





package csrdu.mba.wsa.daemon;

import java.net.*;
import java.io.*;

public class BAClientDaemon {

	public static void main(String[] args) throws IOException {
		ServerSocket serverSocket = null;
		boolean listening = true;

		try {
			serverSocket = new ServerSocket(80);
		} catch (IOException e) {
			System.err.println("Could not listen on port: 4444.");
			System.exit(-1);
		}

		while (listening)
			new BAClientDaemonThread(serverSocket.accept()).start();

		serverSocket.close();
	}

}
