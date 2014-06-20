package kerberos.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Class to handle JDBC connecitons of Authentication Server to its database
 */
public class JdbcConnection {

	private static final String DSN = "Kerberos_DSN";

	/**
	 * Method to retrieve the stored hash of password in the database. The
	 * method creates a JDBC connection to database and attempts to retrieve the
	 * hashed password for the given username. The method requires that
	 *
	 * @param username
	 *            The username for which the hashed password should be
	 *            retrieved.
	 *
	 * @return The hashed password if a user with given username exists,
	 *         otherwise appropriate error message is returned
	 * @throws SQLException
	 * @throws ClassNotFoundException
	 */
	public String getHashedPassword(String username) throws SQLException,
			ClassNotFoundException {

		Statement sql_statement = null;
		ResultSet result = null;
		Connection conn = null;
		String password = null;
		try {
			// Load MS accces driver class
			Class.forName("sun.jdbc.odbc.JdbcOdbcDriver");

			// C:\\databaseFileName.accdb" - location of your database
			String url = "jdbc:odbc:" + DSN;

			// specify url, username, pasword - make sure these are valid
			conn = DriverManager.getConnection(url, "", "");

			System.out.println("Connection to database succesful.");
			sql_statement = conn.createStatement();

			String query = "select Password from Passwords where Username = '"
					+ username + "'";
			result = sql_statement.executeQuery(query);

			/*
			 * If user with given username doesn't exists
			 */
			if (result.next() == false) {
				throw new IllegalArgumentException("Username : " + username
						+ " not found in Database while Authentication");
			}

			password = result.getString("Password");
			if (result != null) {
				result.close();
			}
		} catch (SQLException e) {
			System.err.println("Got an exception! ");
			e.printStackTrace();
			throw e;
		}

		finally {
			// finally block used to release resources
			try {
				if (sql_statement != null)
					sql_statement.close();
			} catch (SQLException se2) {
			}
			try {
				if (conn != null)
					conn.close();
			} catch (SQLException se) {
				se.printStackTrace();
			}// end catch
		}// end finally

		return password;

	}

}
