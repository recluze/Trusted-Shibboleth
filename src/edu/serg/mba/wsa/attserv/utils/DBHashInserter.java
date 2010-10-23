package edu.serg.mba.wsa.attserv.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.sql.*;

public class DBHashInserter {
	public static void main(String args[]) {
		System.out.println("Copyright 2004, R.G.Baldwin");
		try {
			Statement stmt;
			ResultSet rs;

			// Register the JDBC driver for MySQL.
			Class.forName("com.mysql.jdbc.Driver");

			// Define URL of database server for
			// database named JunkDB on the localhost
			// with the default port number 3306.
			String url = "jdbc:mysql://192.168.10.37:3306/integrity";

			// Get a connection to the database for a
			// user named auser with the password
			// drowssap, which is password spelled
			// backwards.
			Connection con = DriverManager.getConnection(url, "root", "");

			// Display URL and connection information
			System.out.println("URL: " + url);
			System.out.println("Connection: " + con);

			// Get a Statement object
			stmt = con.createStatement();

			// As a precaution, delete myTable if it
			// already exists as residue from a
			// previous run. Otherwise, if the table
			// already exists and an attempt is made
			// to create it, an exception will be
			// thrown.
			try {
				stmt.executeUpdate("DROP TABLE myTable");
			} catch (Exception e) {
				System.out.print(e);
				System.out.println("No existing table to delete");
			}// end catch

			String filename = args[0];
			String fileContents = "";

			File file = new File(filename);
			java.io.BufferedReader inFile = new BufferedReader(new FileReader(
					file));
			String line;
			while ((line = inFile.readLine()) != null) {
				fileContents += line;
			}
			inFile.close();

			// Create a table in the database named
			// myTable.
			stmt.executeUpdate(fileContents);

			// // Use the methods of class ResultSet in a
			// // loop to display all of the data in the

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
// // database.
// System.out.println("Display all results:");
// while(rs.next()){
// int theInt= rs.getInt("test_id");
// String str = rs.getString("test_val");
// System.out.println("\ttest_id= " + theInt
// + "\tstr = " + str);
// }// end while loop
//
// // Display the data in a specific row using
// // the rs.absolute method.
// System.out.println(
// "Display row number 2:");
// if( rs.absolute(2) ){
// int theInt= rs.getInt("test_id");
// String str = rs.getString("test_val");
// System.out.println("\ttest_id= " + theInt
// + "\tstr = " + str);
// }// end if
//
// // Delete the table and close the connection
// // to the database
// stmt.executeUpdate("DROP TABLE myTable");
// con.close();
// }catch( Exception e ) {
// e.printStackTrace();
// }// end catch
// }// end main

