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
	ArrayList<Connection> allClients = new ArrayList<Connection>();
	ArrayList<ServerAnnounce> serverAnnounces = new ArrayList<ServerAnnounce>();

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
				register(username, secret);

				log.debug("REGISTER");
				break;
			case "LOGIN":
				username = messageObject.get("username").toString();
				secret = messageObject.get("secret").toString();
				login(username, secret, con);
				log.debug("LOGIN");

				break;
			case "LOGOUT":
				log.debug("LOGOUT");
				break;
				
			case "AUTHENTICATE":
				secret = messageObject.get("secret").toString();
				if(secret.equals(Settings.getSecret())){
					allServers.add(con);
					ServerAnnounce sa = new ServerAnnounce(secret,0,"",0);
					serverAnnounces.add(sa);
					log.info("AUTHENTICATED***YAY");
					
				}
				break;
			}
		} catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// for (Connection connection : connections) {
		// connection.writeMsg(msg);
		// }
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

		return false;
	}

	/*
	 * Other methods as needed
	 */

	public void register(String username, String secret) {
		Iterator it = registeredClients.keySet().iterator();
		boolean exist = false;
		while (it.hasNext()) {
			String name = (String) it.next();
			if (name.equals(username)) {
				// close connection
				exist = true;
				log.info("USERNAME exist");
			}

		}

		if (!exist) {
			registeredClients.put(username, secret);
			log.info("username ->" + username);

			// broadcast to all the servers
			// lock request

		}

	}

	@SuppressWarnings("unchecked")
	public void login(String username, String secret, Connection con) {
		Iterator it = registeredClients.keySet().iterator();
		while (it.hasNext()) {
			String name = (String) it.next();
			String key = registeredClients.get(name);

			if (name.equals(username) && key.equals(secret)) {
				log.info("login sucess");
				JSONObject success = new JSONObject();
				success.put("command", "LOGIN_SUCCESS");
				success.put("info", "logged in as user " + username);
				con.writeMsg(success.toString());
				// load balancing
				int ownLoad = allClients.size();
				int smallestL = 0;
				int small=0;
				for (int i = 0; i < serverAnnounces.size(); i++) {
					if (i == 0) {
						smallestL = serverAnnounces.get(i).getLoad();
					} else {
						if (serverAnnounces.get(i).getLoad() < smallestL) {
							smallestL = serverAnnounces.get(i).getLoad();
							small=i;
						}
					}
				}
				if(smallestL<=ownLoad-2){
					//close the connect
					con.closeCon();
					//redirect,establish a new connection	
					try {
						Socket clientSocket=new Socket(serverAnnounces.get(small).getHostname(),serverAnnounces.get(small).getPort());
						BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
						DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
						
						log.info("Established new connection");
					} catch (UnknownHostException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

				}else{
					log.info("no new connection");
					allClients.add(con);
				}

			}

		}

	}

	class ServerAnnounce {

		String id;
		int load;
		String hostname;
		int port;

		public ServerAnnounce(String id, int load, String hostname, int port) {
			this.id = id;
			this.load = load;
			this.hostname = hostname;
			this.port = port;
		}

		public int getLoad() {
			return load;
		}
		
		public String getHostname(){
			return hostname;
		}
		
		public int getPort(){
			return port;
		}

	}
}
