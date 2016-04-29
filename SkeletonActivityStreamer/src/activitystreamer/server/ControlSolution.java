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
	static ArrayList<ServerAnnounce> serverAnnounces = new ArrayList<ServerAnnounce>();
	String wholeSecret = null;
	private String ID = null;

	int respondCount = 0;
	boolean lockAllow = true;
	String waitingUsername = "";
	String waitingSecret = "";
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
		
		if(Settings.getRemoteHostname() == null){
			wholeSecret=Settings.nextSecret();
			Settings.setSecret(wholeSecret);
			log.info("Whole Secret is: "+wholeSecret);
		}
		ID=Settings.nextSecret();
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
		con.closeCon();
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
				
				register(username, secret, con);
		
				log.debug("REGISTER");
				break;
			case "LOGIN":
				username = messageObject.get("username").toString();
				secret = messageObject.get("secret").toString();
				login(username, secret, con);
				log.debug("LOGIN");

				break;
			case "LOGOUT":
				// remove connection from client hash table
				allClients.remove(con);
				// close connection
				this.connectionClosed(con);
				log.debug("LOGOUT");
				break;

			case "AUTHENTICATE":
				secret = messageObject.get("secret").toString();
				if (secret.equals(Settings.getSecret())) {
					allServers.add(con);
					log.info("AUTHENTICATED***YAY**Size of SA = ***"
							+ serverAnnounces.size());

				}else{
					JSONObject fail = new JSONObject();
					fail.put("command", "AUTHENTICATION_FAIL");
					fail.put("info","the supplied secret is incorrect: "+secret);
					con.writeMsg(fail.toJSONString());
					//close connection 
					this.connectionClosed(con);
				}
				break;
			case "AUTHENTICATION_FAIL":
				this.connectionClosed(con);
				break;
			case "SERVER_ANNOUNCE":
				receiveServerAnnounce(messageObject,con);
				break;
			case "LOCK_REQUEST":
				//redirect to other servers
				for(Connection connect:allServers){
					if(connect!=con){
						connect.writeMsg(msg);
					}
				}
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
					registeredClients.put(username, secret); 
					JSONObject allow = new JSONObject();
					allow.put("command", "LOCK_ALLOWED");
					allow.put("username", username);
					allow.put("secret", secret);
					allow.put("server", ID);
					
					for(Connection connect: allServers){
						connect.writeMsg(allow.toJSONString());
					}
					log.info("Sent LOCK_ALLOWED to all the servers");
					
				}
				break;
				
			case "LOCK_DENIED":
				//redirect to other servers
				for(Connection connect:allServers){
					if(connect!=con){
						connect.writeMsg(msg);
					}
				}
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
				//redirect to other servers
				for(Connection connect:allServers){
					if(connect!=con){
						connect.writeMsg(msg);
					}
				}
				username = messageObject.get("username").toString();
				secret = messageObject.get("secret").toString();
				
				if(waitingUsername.equals(username)){
					respondCount++;
				}
				log.info("---------->respondCount= "+respondCount);
				break;
				
			case "ACTIVITY_MESSAGE":
				username = messageObject.get("username").toString();
				if(allClients.containsValue(username) || username.equals("anonymous")){
					String activity = messageObject.get("activity").toString();
					
					JSONObject activityObject;
					JSONParser par= new JSONParser();
					activityObject = (JSONObject) par.parse(activity);
					activityObject.put("authenticated_user", username);
					
					JSONObject broadcast = new JSONObject();
					broadcast.put("command","ACTIVITY_BROADCAST");
					broadcast.put("activity",activityObject);
					
					for(Connection connect:allServers){
						connect.writeMsg(broadcast.toJSONString());
					}
					Iterator it = allClients.keySet().iterator();
					while (it.hasNext()) {
						Connection connect = (Connection)it.next();
						connect.writeMsg(broadcast.toJSONString());			
					}
					
				}else{
					JSONObject fail = new JSONObject();
					fail.put("command", "AUTHENTICATION_FAIL");
					fail.put("info", username +" has not logged in");
					con.writeMsg(fail.toJSONString());
				}
				
				break;
				
			case "ACTIVITY_BROADCAST":
				Iterator it = allClients.keySet().iterator();
				while (it.hasNext()) {
					Connection connect = (Connection)it.next();
					connect.writeMsg(msg);
						
				}
				for(Connection connect:allServers){
					if(connect!=con){
						connect.writeMsg(msg);
					}
				}
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
		serverAnnounce.put("id", this.ID);
		serverAnnounce.put("load", allClients.size());
		serverAnnounce.put("hostname", Settings.getLocalHostname());
		serverAnnounce.put("port", Settings.getLocalPort());

		for (Connection c : allServers) {
			c.writeMsg(serverAnnounce.toJSONString());
		}

		return false;
	}

	/*
	 * Other methods as needed
	 */
	public void receiveServerAnnounce(JSONObject messageObject, Connection con){
		String hostname = messageObject.get("hostname").toString();
		int port = Integer.parseInt(messageObject.get("port")
				.toString());
		String msgID = messageObject.get("id").toString();
		int load = Integer.parseInt(messageObject.get("load")
				.toString());
		log.info("=======LOAD is: "+load);

		 //check if already that one already exists
		boolean SerInformationExist=false;
		for(int i=0;i<serverAnnounces.size();i++){
			if(msgID.equals(serverAnnounces.get(i).getID())){
				serverAnnounces.get(i).setHostname(hostname);
				serverAnnounces.get(i).setLoad(load);
				serverAnnounces.get(i).setPort(port);
				log.info("=======sa LOAD:"+serverAnnounces.get(i).getLoad());
				SerInformationExist=true;
			}
		}
		
		if(!SerInformationExist){
			//add to the serverAnnounce array
			ServerAnnounce sA=new ServerAnnounce();
			sA.setHostname(hostname);
			sA.setID(msgID);
			sA.setLoad(load);
			sA.setPort(port);
			serverAnnounces.add(sA);
			log.info("=======sa LOAD:"+sA.getLoad());
		}
		//send that message to other server related to it except the one send the message
		for(Connection connect:allServers){
			if(connect!=con){
				connect.writeMsg(messageObject.toJSONString());
			}
		}

		log.info("*****WORKING*****");
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public synchronized void register(String username, String secret, Connection con) {
		
		
		Iterator it = registeredClients.keySet().iterator();
		boolean exist = false;
		if (!allClients.containsKey(con)) {
			while (it.hasNext()) {
				String name = (String) it.next();
				if (name.equals(username)) {
					exist = true;
					log.info("USERNAME exist");
					JSONObject fail = new JSONObject();
					fail.put("command", "REGISTER_FAILED");
					fail.put("info", username
							+ " is already registered with the system");
					con.writeMsg(fail.toJSONString());
					// close connection
					this.connectionClosed(con);
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
				log.info("---------Server Size---------"+serverAnnounces.size());
				log.info("---------respond Size---------"+respondCount);
				while(respondCount!=serverAnnounces.size()){
					try {
						wait(5000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if(respondCount==serverAnnounces.size()){
					//log.info("---------1.I'm executed---------");
					if (lockAllow == true){
						//log.info("---------2.I'm executed---------");
						JSONObject success = new JSONObject();
						success.put("command", "REGISTER_SUCCESS");
						success.put("info", "register success for " + username);
						con.writeMsg(success.toJSONString());	
						respondCount = 0;
						log.info("***lock Allow = true ***");
						
					}else{
						JSONObject fail = new JSONObject();
						fail.put("command", "REGISTER_FAILED");
						fail.put("info", username+ " is already registered with the system");
						con.writeMsg(fail.toJSONString());
						log.info("***lock Allow = false ***");
						respondCount = 0;
						lockAllow = true;
						
						this.connectionClosed(con);
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
		
		if (registeredClients.containsKey(username)) {

			String key = registeredClients.get(username);

			if (key.equals(secret)) {
				//log.info("login sucess");
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
					this.connectionClosed(con);

				} else {
					log.info("no new connection");
					allClients.put(con, username);
				}

			} else {
				JSONObject fail = new JSONObject();
				fail.put("command", "LOGIN_FAILED");
				fail.put("info",
						"1. attempt to login with invalid username or wrong secret");
				con.writeMsg(fail.toJSONString());
				// close connection
				this.connectionClosed(con);
			}

		} else {
			JSONObject fail = new JSONObject();
			fail.put("command", "LOGIN_FAILED");
			fail.put("info",
					"2. attempt to login with invalid username or wrong secret");
			con.writeMsg(fail.toJSONString());
			// close connection
			this.connectionClosed(con);
		}

	}

	class ServerAnnounce {

		String id=null;
		int load;
		String hostname=null;
		int port;

		public ServerAnnounce(String id, int load,
				String hostname, int port) {
			this.id = id;
			this.load = load;
			this.hostname = hostname;
			this.port = port;
		}
		public ServerAnnounce(){
			
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

		public String getID(){
			return this.id;
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
