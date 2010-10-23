/*
 * Copyright (C) 2008 Security Engineering Research Group, 
 * Institute of Management Sciences, Peshawar, Pakistan.
 * http://serg.imsciences.edu.pk 
 * authors: Nauman and Tamleek 
 */

package edu.serg.mba.wsa.attserv.utils;

import java.util.StringTokenizer;
import java.io.*;

public class HashInsertQueryGenerator {

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		if (args.length < 2)
			return;
		String filename = args[0];
		String fileContents = "";

		File file = new File(filename);
		java.io.BufferedReader inFile = new BufferedReader(new FileReader(file));
		String line;
		while ((line = inFile.readLine()) != null) {
			fileContents += line;
		}
		inFile.close();
		// create output file
		File ofile = new File(args[1]);
		FileWriter fw = new FileWriter(ofile, false);
		PrintWriter pw = new PrintWriter(fw, true);

		// tokenize to get hash and path
		StringTokenizer st = new StringTokenizer(fileContents);

		while (st.hasMoreTokens()) {
			st.nextToken();
			String strInsertQuery;
			strInsertQuery = "insert into KNOWN_GOOD values ('"
					+ st.nextToken() + "', '" + st.nextToken() + "', '');";
			// or sbin

			pw.println(strInsertQuery);
			// put into file

			pw.flush();
		}
		pw.close();
	}
}
