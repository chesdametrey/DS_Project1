package activitystreamer.server;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import activitystreamer.util.Settings;

public class ControlSolution extends Control {
	private static final Logger log = LogManager.getLogger();

	/*
	 * additional variables as needed
	 */
	Hashtable<String, String> registeredClients = new Hashtable<String, String>();
	ArrayList<Connection> allServers = new ArrayList<Connection>();
	Hashtable<Connection, String> allClients = new Hashtable<Connection, String>();
	ArrayList<ServerAnnounce> serverAnnounces = new ArrayList<ServerAnnounce>();
	String wholeSecret = "";
	private String id = "";

	int respondCount = 0;
	boolean lockAllow = true;
	String waitingUsername = null;
	String waitingSecret = null;
	// since control and its subclasses are singleton, we get the singleton this
	// way
	public static ControlSolution getInstance() {
		if (control == null) {
			control = new ControlSolution();
		}
		return (ControlSolution) control;
	}

	public ControlSolution() {
		super();
		/*
		 * Do some further initialization here if necessary
		 */

		// check if we should initiate a connection and do so if necessary
		initiateConnection();
		// start the server's activity loop
		// it will call doActivity every few seconds
		start();
	}

	/*
	 * a new incoming connection
	 */
	@Override
	public Connection incomingConnection(Socket s) throws IOException {
		Connection con = super.incomingConnection(s);
		/*
		 * do additional things here
		 */
		// load balancing

		return con;
	}

	/*
	 * a new outgoing connection
	 */
	@SuppressWarnings("unchecked")
	@Override
	public Connection outgoingConnection(Socket s) throws IOException {
		Connection con = super.outgoingConnection(s);
		/*
		 * do additional things here
		 */
		JSONObject serverMessage = new JSONObject();
		serverMessage.put("command", "AUTHENTICATE");
		serverMessage.put("secret", Settings.getSecret());
		con.writeMsg(serverMessage.toString());

		allServers.add(con);
		ServerAnnounce sa = new ServerAnnounce(con, Settings.getSecret(), 0,
				"", 0);
		serverAnnounces.add(sa);
		return con;
	}

	/*
	 * the connection has been closed
	 */
	@Override
	public void connectionClosed(Connection con) {
		super.connectionClosed(con);
		/*
		 * do additional things here
		 */
	}

	/*
	 * process incoming msg, from connection con return true if the connection
	 * should be closed, false otherwise
	 */
	@SuppressWarnings("unchecked")
	@Override
	public synchronized boolean process(Connection con, String msg) {
		/*
		 * do additional work here return true/false as appropriate
		 */
		log.info("Msg received1");
		String command, username, secret;
		JSONParser parser = new JSONParser();
		JSONObject messageObject;
		log.info("Msg received");
		log.info(msg);
		try {
			messageObject = (JSONObject) parser.parse(msg);
			// access message object
			command = messageObject.get("command").toString();
			switch (command) {
			case "REGISTER":
				username = messageObject.get("username").toString();
				secret = messageObject.get("secret").toString();
				
				/* if(!allClients.containsKey(username)){ */
				register(username, secret, con);
				/*
				 * }else{ JSONObject invalid = new JSONObject();
				 * invalid.put("command", "INVALID_MESSAGE");
				 * invalid.put("info",
				 * "Can not register new user while you are logged in");
				 * con.writeMsg(invalid.toJSONString()); }
				 */
				log.debug("REGISTER");
				break;
			case "LOGIN":
				username = messageObject.get("username").toString();
				secret = messageObject.get("secret").toString();
				login(username, secret, con);
				log.debug("LOGIN");

				break;
			case "LOGOUT":
				// close connection
				// remove connection from client hash table
				allClients.remove(con);
				log.debug("LOGOUT");
				break;

			case "AUTHENTICATE":
				secret = messageObject.get("secret").toString();
				if (secret.equals(Settings.getSecret())) {
					allServers.add(con);
					ServerAnnounce sa = new ServerAnnounce(con, secret, 0, "",
							0);
					serverAnnounces.add(sa);
					log.info("AUTHENTICATED***YAY**Size of SA = ***"
							+ serverAnnounces.size());

				}
				break;
			case "SERVER_ANNOUNCE":
				String hostname = messageObject.get("hostname").toString();
				int port = Integer.parseInt(messageObject.get("port")
						.toString());
				String id = messageObject.get("id").toString();
				int load = Integer.parseInt(messageObject.get("load")
						.toString());

				log.info("***SIZE***" + serverAnnounces.size());
				for (ServerAnnounce sa : serverAnnounces) {
					// if(sa.getCon().equals(con)){
					sa.setHostname(hostname);
					sa.setLoad(load);
					sa.setPort(port);
					sa.setID(id);
					log.info("load: " + sa.getLoad() + " HN:"
							+ sa.getHostname() + " ************");
					// }

				}

				log.info("*****WORKING*****");
				break;
			case "LOCK_REQUEST":
				username = messageObject.get("username").toString();
				secret = messageObject.get("secret").toString();
				if(registeredClients.containsKey(username)){
					JSONObject deny = new JSONObject();
					deny.put("command", "LOCK_DENIED");
					deny.put("username", username);
					deny.put("secret", secret);
					
					for(Connection connect: allServers){
						connect.writeMsg(deny.toJSONString());
					}
					
					log.info("Sent LOCK_DENIED to all the servers");
					
					
				}else{
					JSONObject allow = new JSONObject();
					allow.put("command", "LOCK_ALLOWED");
					allow.put("username", username);
					allow.put("secret", secret);
					allow.put("server", "");
					
					for(Connection connect: allServers){
						connect.writeMsg(allow.toJSONString());
					}
					log.info("Sent LOCK_ALLOWED to all the servers");
					
				}
				break;
				
			case "LOCK_DENIED":
				username = messageObject.get("username").toString();
				secret = messageObject.get("secret").toString();
				
				if (registeredClients.containsKey(username)){
					registeredClients.remove(username);
				}
				if(waitingUsername.equals(username)){
					respondCount++;
					lockAllow = false;
					
				}
				break;
				
			case "LOCK_ALLOWED":
				username = messageObject.get("username").toString();
				secret = messageObject.get("secret").toString();
				
				if(waitingUsername.equals(username)){
					respondCount++;
				}
				log.info("---------->respondCount= "+respondCount);
				break;
			}
		} catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		return false;
	}

	/*
	 * Called once every few seconds Return true if server should shut down,
	 * false otherwise
	 */
	@Override
	public boolean doActivity() {
		/*
		 * do additional work here return true/false as appropriate
		 */

		JSONObject serverAnnounce = new JSONObject();
		serverAnnounce.put("command", "SERVER_ANNOUNCE");
		serverAnnounce.put("id", Settings.getSecret());
		serverAnnounce.put("load", allClients.size());
		serverAnnounce.put("hostname", Settings.getLocalHostname());
		serverAnnounce.put("port", Settings.getLocalPort());

		for (Connection c : allServers) {
			c.writeMsg(serverAnnounce.toJSONString());
		}
		/*
		 * for(Connection c: this.connections){
		 * c.writeMsg(serverAnnounce.toJSONString()); }
		 */
		log.info("**********");
		return false;
	}

	/*
	 * Other methods as needed
	 */

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public synchronized void register(String username, String secret, Connection con) {
		
		
		Iterator it = registeredClients.keySet().iterator();
		boolean exist = false;
		if (!allClients.containsKey(con)) {
			while (it.hasNext()) {
				String name = (String) it.next();
				if (name.equals(username)) {
					// close connection
					exist = true;
					log.info("USERNAME exist");
					JSONObject fail = new JSONObject();
					fail.put("command", "REGISTER_FAILED");
					fail.put("info", username
							+ " is already registered with the system");
					con.writeMsg(fail.toJSONString());
				}

			}

			if (!exist) {
				registeredClients.put(username, secret);
				log.info("username ->" + username);

				// broadcast to all the servers
				// lock request
				
				JSONObject lock = new JSONObject();
				lock.put("command", "LOCK_REQUEST");
				lock.put("username", username);
				lock.put("secret", secret);
				
				for(Connection connect: allServers){
					connect.writeMsg(lock.toJSONString());
				}
				waitingUsername = username;
				waitingSecret = secret;
				
				//check count and flag
				log.info("---------Server Size---------"+allServers.size());
				log.info("---------respond Size---------"+respondCount);
				while(respondCount!=allServers.size()){
					try {
						wait(5000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if(respondCount==allServers.size()){
					log.info("---------1.I'm executed---------");
					if (lockAllow == true){
						log.info("---------2.I'm executed---------");
						JSONObject success = new JSONObject();
						success.put("command", "REGISTER_SUCCESS");
						success.put("info", "register success for " + username);
						con.writeMsg(success.toJSONString());	
						respondCount = 0;
						log.info("***lock Allow = true ***");
						
						/*
						 * log in user ????????????????
						 * 
						 */
						
						login(username,secret,con);
					}else{
						JSONObject fail = new JSONObject();
						fail.put("command", "REGISTER_FAILED");
						fail.put("info", username+ " is already registered with the system");
						con.writeMsg(fail.toJSONString());
						log.info("***lock Allow = false ***");
						respondCount = 0;
						lockAllow = true;
						
					}
				}

			}
		} else {
			JSONObject invalid = new JSONObject();
			invalid.put("command", "INVALID_MESSAGE");
			invalid.put("info",
					"Can not register new user while you are logged in");
			con.writeMsg(invalid.toJSONString());

		}

	}
	

	@SuppressWarnings("unchecked")
	public void login(String username, String secret, Connection con) {
		// Iterator it = registeredClients.keySet().iterator();
		// while (it.hasNext()) {
		// String name = (String) it.next();
		if (registeredClients.containsKey(username)) {

			String key = registeredClients.get(username);

			if (key.equals(secret)) {
				log.info("login sucess");
				JSONObject success = new JSONObject();
				success.put("command", "LOGIN_SUCCESS");
				success.put("info", "logged in as user " + username);
				con.writeMsg(success.toString());
				// load balancing
				int ownLoad = allClients.size();
				int smallestL = 0;
				int small = 0;
				for (int i = 0; i < serverAnnounces.size(); i++) {
					if (i == 0) {
						smallestL = serverAnnounces.get(i).getLoad();
					} else {
						if (serverAnnounces.get(i).getLoad() < smallestL) {
							smallestL = serverAnnounces.get(i).getLoad();
							small = i;
						}
					}
				}
				log.info("***smallestL = " + smallestL + "**ownLoad = "
						+ ownLoad);
				if (smallestL <= ownLoad - 2) {
					// close the connect
					// con.closeCon();
					// redirect,establish a new connection
					JSONObject redirect = new JSONObject();
					redirect.put("command", "REDIRECT");
					redirect.put("hostname", serverAnnounces.get(small)
							.getHostname());
					redirect.put("port", serverAnnounces.get(small).getPort());
					con.writeMsg(redirect.toJSONString());

					log.info("***host***"
							+ serverAnnounces.get(small).getHostname()
							+ "****port**"
							+ serverAnnounces.get(small).getPort());

				} else {
					log.info("no new connection");
					allClients.put(con, username);
				}

			} else {
				JSONObject fail = new JSONObject();
				fail.put("command", "LOGIN_FAILED");
				fail.put("info",
						"attempt to login with invalid username or wrong secret");
				con.writeMsg(fail.toJSONString());
				// close connection
			}

		} else {
			JSONObject fail = new JSONObject();
			fail.put("command", "LOGIN_FAILED");
			fail.put("info",
					"attempt to login with invalid username or wrong secret");
			con.writeMsg(fail.toJSONString());
			// close connection
		}

	}

	class ServerAnnounce {

		String id;
		int load;
		String hostname;
		int port;
		Connection con;

		public ServerAnnounce(Connection con, String id, int load,
				String hostname, int port) {
			this.con = con;
			this.id = id;
			this.load = load;
			this.hostname = hostname;
			this.port = port;
		}

		public int getLoad() {
			return load;
		}

		public String getHostname() {
			return hostname;
		}

		public int getPort() {
			return port;
		}

		public Connection getCon() {
			return con;
		}

		public void setLoad(int load) {
			this.load = load;
		}

		public void setHostname(String hostname) {
			this.hostname = hostname;
		}

		public void setPort(int port) {
			this.port = port;
		}

		public void setID(String id) {
			this.id = id;
		}

	}
}
