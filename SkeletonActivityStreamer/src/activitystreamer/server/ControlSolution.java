package activitystreamer.server;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Hashtable;
import java.util.Iterator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import activitystreamer.client.ClientSolution;
import activitystreamer.util.Settings;
import sun.misc.BASE64Encoder;

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
	private JSONParser parser = new JSONParser();

	int respondCount = 0;
	boolean lockAllow = true;
	String waitingUsername = "";
	String waitingSecret = "";
	
	static PublicKey publicKey;  //its own public key
	static PrivateKey privateKey;  //its own private key
	//to store others public key
	//static Hashtable<Connection, PublicKey> pubKeyList=new Hashtable<Connection,PublicKey>();
	static PublicKey parentPubKey;
	//to store shared key
	static Hashtable<Connection, SecretKey> sharedKeyList=new Hashtable<Connection, SecretKey>();
	
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
		if(Settings.getRemoteHostname() == null){
			wholeSecret=Settings.nextSecret();
			Settings.setSecret(wholeSecret);
			log.info("Whole Secret is: "+wholeSecret);
		}
		ID=Settings.nextSecret();
		
		//generate pub/priv key pair
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
		    KeyPair keyPair = keyGen.generateKeyPair();
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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
		/*JSONObject serverMessage = new JSONObject();
		serverMessage.put("command", "AUTHENTICATE");
		//serverMessage.put("requestPubKey", "");
		serverMessage.put("secret", Settings.getSecret());
		con.writeMsg(serverMessage.toString());*/
		JSONObject requestKey=new JSONObject();
		requestKey.put("command", "REQUEST_PUBKEY");
		con.writeMsg(requestKey.toJSONString());

		allServers.add(con);
		return con;
	}

	/*
	 * the connection has been closed
	 */
	@Override
	public void connectionClosed(Connection con) {
		super.connectionClosed(con);
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
		
		//******CHECK HERE MSG IS CORRUPTED
		log.info("********"+"JSONVALID?= "+isGoodJson(msg)+" ----- "+ msg);
		if(!isGoodJson(msg)){
			log.info("=========");
			con.newVersion=true;
			msg=decrypt(con,msg);
			}
			
		log.info("Msg received1");
		String command;
		JSONParser parser = new JSONParser();
		JSONObject messageObject;
		
		boolean closeCon=false;
		
		try {
			messageObject = (JSONObject) parser.parse(msg);
			/*if(messageObject.containsKey("encrpte")){
				con.newVersion=true;
				msg=decrypt(msg);
				messageObject = (JSONObject) parser.parse(msg);
			}*/
			// access message object
			command = messageObject.get("command").toString();
			switch (command) {
			case "REGISTER":
				if(messageObject.containsKey("username") && messageObject.containsKey("secret")){
					String username = messageObject.get("username").toString();
					String secret = messageObject.get("secret").toString();
					register(username, secret, con);
					log.debug("REGISTER");
				}else{
					JSONObject invalid = new JSONObject();
					invalid.put("command", "INVALID_MESSAGE");
					invalid.put("info","Invalid Message Sent");
					con.writeMsg(invalid.toJSONString());
				}
				break;
			case "LOGIN":
				if(messageObject.containsKey("username") && messageObject.containsKey("secret")){
					String username = messageObject.get("username").toString();
					String secret = messageObject.get("secret").toString();
					login(username, secret, con);
					log.debug("LOGIN");
				}else{
					JSONObject invalid = new JSONObject();
					invalid.put("command", "INVALID_MESSAGE");
					invalid.put("info","Invalid Message Sent");
					con.writeMsg(invalid.toJSONString());
				}

				break;
			case "LOGOUT":
				// remove connection from client hash table
				allClients.remove(con);
				// close connection
				//this.connectionClosed(con);
				closeCon=true;
				log.debug("LOGOUT");
				break;

			case "AUTHENTICATE":
				closeCon=receiveAuthentication(messageObject,con);
				break;
				
			case "AUTHENTICATION_FAIL":
				//this.connectionClosed(con);
				closeCon=true;
				break;
			case "AUTHENTICATED":
//				Iterator it = (Iterator) messageObject.keySet(); 
//				while(it.hasNext()){
//					String key = (String) it.next();  
//	                String value = (String) messageObject.get(key);
//	                registeredClients.put(key, value);
//				}
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
				String username = messageObject.get("username").toString();
				String secret = messageObject.get("secret").toString();
				processLockRequest(con,username,secret);
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
				//log.info("---------->respondCount= "+respondCount);
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
					Iterator iterator = allClients.keySet().iterator();
					while (iterator.hasNext()) {
						Connection connect = (Connection)iterator.next();
						connect.writeMsg(broadcast.toJSONString());			
					}
					
				}else{
					JSONObject fail = new JSONObject();
					fail.put("command", "AUTHENTICATION_FAIL");
					fail.put("info", username +" has not logged in");
					con.writeMsg(fail.toJSONString());
					closeCon=true;
				}
				
				break;
				
			case "ACTIVITY_BROADCAST":
				Iterator ite = allClients.keySet().iterator();
				while (ite.hasNext()) {
					Connection connect = (Connection)ite.next();
					connect.writeMsg(msg);
						
				}
				for(Connection connect:allServers){
					if(connect!=con){
						connect.writeMsg(msg);
					}
				}
				break;
			case "REQUEST_PUBKEY":
				JSONObject response=new JSONObject();
				response.put("command", "RESPONSE_PUBKEY");
				response.put("pubkey", publicKeyToString(publicKey));
				log.info("respose Json:"+response.toJSONString());
				con.writeMsg(response.toJSONString());
				break;
			case "RESPONSE_PUBKEY":
				String pubKeyString=(String) messageObject.get("pubkey");
				PublicKey pubkey=stringToPublicKey( pubKeyString);
				parentPubKey=pubkey;
				//generate shared key for this connection
				try {
					KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
					SecretKey sharedKey = keyGenerator.generateKey();
					sharedKeyList.put(con, sharedKey);
					//respond with shared key and authentication message
					JSONObject respond=new JSONObject();
					respond.put("command", "AUTHENTICATE");
					respond.put("secret", Settings.getSecret());
					respond.put("sharedkey", secretKeyToString(sharedKey));
					//send msg
				    con.writeMsg(respond.toJSONString());
					
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				break;
				
			default:
				JSONObject invalid = new JSONObject();
				invalid.put("command", "INVALID_MESSAGE");
				invalid.put("info","Invalid Message Sent");
				con.writeMsg(invalid.toJSONString());
				break;
			}
		} catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		return closeCon;
	}

	/*
	 * Called once every few seconds Return true if server should shut down,
	 * false otherwise
	 */
	@SuppressWarnings("unchecked")
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
			
			//******************ERROR***************
			c.writeMsgWithSharedkey(serverAnnounce.toJSONString());
		}

		return false;
	}

	/*
	 * Other methods as needed
	 */
	public synchronized void processLockRequest(Connection con,String username,String secret){
		
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
	}
	
	public synchronized boolean receiveAuthentication(JSONObject messageObject, Connection con){
		String secret = messageObject.get("secret").toString();
		
		if (secret.equals(Settings.getSecret())) {
			allServers.add(con);
			log.info("New Server AUTHENTICATED");
			//add shared key
			if(messageObject.containsKey("sharedkey")){
				String keyStr=(String)messageObject.get("sharedkey");
				SecretKey secretKey=stringToSecretKey(keyStr);
				sharedKeyList.put(con, secretKey);
			}
			//improve challenge, send registedUsers list
			JSONObject success=new JSONObject();
			success.put("command", "AUTHENTICATED");
			success.putAll(registeredClients);
			
			con.writeMsg(success.toJSONString());

		}else{
			JSONObject fail = new JSONObject();
			fail.put("command", "AUTHENTICATION_FAIL");
			fail.put("info","the supplied secret is incorrect: "+secret);
			
			con.writeMsg(fail.toJSONString());
			//close connection 
			//this.connectionClosed(con);
			return true;
		}
		
		return false;
	}
	public void receiveServerAnnounce(JSONObject messageObject, Connection con){
		String hostname = messageObject.get("hostname").toString();
		int port = Integer.parseInt(messageObject.get("port")
				.toString());
		String msgID = messageObject.get("id").toString();
		int load = Integer.parseInt(messageObject.get("load")
				.toString());
		//log.info("=======LOAD is: "+load);

		 //check if already that one already exists
		boolean SerInformationExist=false;
		for(int i=0;i<serverAnnounces.size();i++){
			if(msgID.equals(serverAnnounces.get(i).getID())){
				serverAnnounces.get(i).setHostname(hostname);
				serverAnnounces.get(i).setLoad(load);
				serverAnnounces.get(i).setPort(port);
				//log.info("=======SA LOAD:"+serverAnnounces.get(i).getLoad());
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
			//log.info("=======SA LOAD:"+sA.getLoad());
		}
		//send that message to other server related to it except the one send the message
		for(Connection connect:allServers){
			if(connect!=con){
				connect.writeMsg(messageObject.toJSONString());
			}
		}

	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public synchronized void register(String username, String secret, Connection con) {
		
		
		Iterator it = registeredClients.keySet().iterator();
		boolean exist = false;
		//check of the user name is already registered
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
				//if the user name hasn't been registered
				registeredClients.put(username, secret);
				log.info("username ->" + username);

				//Lock request object
				JSONObject lock = new JSONObject();
				lock.put("command", "LOCK_REQUEST");
				lock.put("username", username);
				lock.put("secret", secret);
				// broadcast to all the servers
				// lock request	
				for(Connection connect: allServers){
					connect.writeMsg(lock.toJSONString());
				}
				waitingUsername = username;
				waitingSecret = secret;
				
				//check count and flag
				//log.info("---------Server Size---------"+serverAnnounces.size());
				//log.info("---------respond Size---------"+respondCount);
				while(respondCount!=serverAnnounces.size()){
					try {
						wait(3000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				
				//Server got all the responses from other servers
				if(respondCount==serverAnnounces.size()){
					//log.info("---------1.I'm executed---------");
					if (lockAllow == true){
						//log.info("---------2.I'm executed---------");
						JSONObject success = new JSONObject();
						success.put("command", "REGISTER_SUCCESS");
						success.put("info", "register success for " + username+" secret is: "+secret);
						con.writeMsg(success.toJSONString());	
						respondCount = 0;
						log.info("---lock Allow = true---");
						
					}else{
						JSONObject fail = new JSONObject();
						fail.put("command", "REGISTER_FAILED");
						fail.put("info", username+ " is already registered with the system");
						con.writeMsg(fail.toJSONString());
						log.info("---lock Allow = false---");
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
		if(username.equals("anonymous")&&secret.equals("")){
			callInLogin(username, secret, con);
		}else if (registeredClients.containsKey(username)) {

			String key = registeredClients.get(username);

			if (key.equals(secret)) {
				callInLogin(username, secret, con);
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
	@SuppressWarnings("unchecked")
	public void callInLogin(String username, String secret, Connection con){
		JSONObject success = new JSONObject();
		success.put("command", "LOGIN_SUCCESS");
		success.put("info", "logged in as user " + username);
		con.writeMsg(success.toString());
		// load balancing
		if(serverAnnounces.size()>0){
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
		//log.info("***smallestL = " + smallestL + "**ownLoad = "+ ownLoad);
		if (smallestL <= ownLoad - 2) {
			// redirect,establish a new connection
			JSONObject redirect = new JSONObject();
			redirect.put("command", "REDIRECT");
			redirect.put("hostname", serverAnnounces.get(small)
					.getHostname());
			redirect.put("port", serverAnnounces.get(small).getPort());
			con.writeMsg(redirect.toJSONString());

			log.info("Host =>"+ serverAnnounces.get(small).getHostname()
					+ " Port =>"+ serverAnnounces.get(small).getPort());
			this.connectionClosed(con);

		} else {
			log.info("no new connection");
			allClients.put(con, username);
		}
		}else{
			allClients.put(con, username);
		}
	}
	 public boolean isGoodJson(String json) {  
		 /*JSONObject ob;
	        try {  
	            ob = (JSONObject)new JSONParser().parse(json);  
	            return true;  
	        } catch (JsonParseException e) {  
	            log.error("bad json: " + json);  
	            return false;  
	        } catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				log.error("bad json: " + json);  
	            return false; 
			} */
		 
		 JSONObject obj;
			try {
				obj = (JSONObject) parser.parse(json);
				//ClientSolution.getInstance().sendActivityObject(obj);
				return true;
			} catch (ParseException e1) {
				log.error("invalid JSON object entered into input text field, data not sent");
				return false;
			}

	    } 
	 public String decrypt(Connection con, String msg){
		 log.info("msg???????"+msg);
		
		// byte[] receivedMsg=stringToByte(msg);
		 //byte[] b = new BigInteger(msg.toString(),16).toByteArray();
		 HexBinaryAdapter adapter = new HexBinaryAdapter();
	     byte[] b = adapter.unmarshal(msg);
		
		 //byte[] encode = stringToByte(msg);
		 log.info("**AFTER HEX**:"+new String(b));
		// byte[] receivedMsg=msg.getBytes();

		 byte[] text = null;
		 log.info("***** PASS THROUGH???????****** "+ sharedKeyList.get(con) +"size:"+sharedKeyList.size());
		 
		 //***ERROR *** CHANGE FROM this -> con
			if(sharedKeyList.containsKey(con)){
				
				//decrypt with sharedkey
				SecretKey sharedkey=sharedKeyList.get(con);
				log.info("*****decrypt shared key: "+ sharedkey);
				try {
					Cipher desCipher = Cipher.getInstance("DES");
					desCipher.init(Cipher.DECRYPT_MODE, sharedkey);
					text=desCipher.doFinal(b);
					log.info("***** DNCRYPTED******:"+new String(text));
				} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			else{
				//decrypt with privkey
				try {
					log.info("aaaaaaaaa!");
					Cipher cipher = Cipher.getInstance("RSA");
					log.info("aaaaapubKeyThisSide:"+publicKey);
					cipher.init(Cipher.DECRYPT_MODE, privateKey);
					text=cipher.doFinal(b);
					log.info("text!!!!!!!"+text);
				} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			//String jsonStr=new sun.misc.BASE64Encoder().encodeBuffer(text);
			//String jsonStr=byteToString(text);
			String jsonStr=new String(text);
			return jsonStr;
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
	public PublicKey stringToPublicKey(String string)
	{
	byte[]  strByte = DatatypeConverter.parseBase64Binary(string);
	KeyFactory keyFact = null;
	PublicKey returnKey = null;
	try {
		keyFact = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(strByte);
		returnKey = keyFact.generatePublic(x509KeySpec);
	} catch (NoSuchAlgorithmException | InvalidKeySpecException e1) {
		// TODO Auto-generated catch block
		e1.printStackTrace();
	}
	
	return returnKey; 
	} 
	
	public String publicKeyToString(PublicKey p) {

	    byte[] publicKeyBytes = p.getEncoded();
	    BASE64Encoder encoder = new BASE64Encoder();
	    return encoder.encode(publicKeyBytes);
	}
	public String secretKeyToString(SecretKey k){
		String encodedKey=Base64.getEncoder().encodeToString(k.getEncoded());
		return encodedKey;
	}
	public SecretKey stringToSecretKey(String s){
		byte[] decodedKey = Base64.getDecoder().decode(s);
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
		return originalKey;
	}
	public String byteToString(byte[] b){
		String str=new sun.misc.BASE64Encoder().encodeBuffer(b);
		return str;
	}
	public byte[] stringToByte(String s){
		byte[] text = null;
		 
		try {
			text = new sun.misc.BASE64Decoder().decodeBuffer(s);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return text;
	}
	
}
