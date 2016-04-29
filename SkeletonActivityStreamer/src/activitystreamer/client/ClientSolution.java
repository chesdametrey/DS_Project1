package activitystreamer.client;

import java.io.*;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import activitystreamer.util.Settings;

public class ClientSolution extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSolution clientSolution;
	private static boolean term  = false;
	private TextFrame textFrame;

	/*
	 * additional variables
	 */
	private Socket clientSocket;
	private BufferedReader inFromServer;
	private DataOutputStream outToServer;
	private String remoteHost = Settings.getRemoteHostname();
	private int remotePort = Settings.getRemotePort();

	// this is a singleton object
	public static ClientSolution getInstance() {
		if (clientSolution == null) {
			clientSolution = new ClientSolution();
		}
		return clientSolution;
	}

	@SuppressWarnings("unchecked")
	public ClientSolution() {
		/*
		 * some additional initialization
		 */

		// open the gui
		log.debug("opening the gui");
		textFrame = new TextFrame();
		try {
			clientSocket = new Socket(this.remoteHost, this.remotePort);
			System.out.println("Connect to Server " + this.remoteHost + ":"
					+ remotePort + " successfully.");
			inFromServer = new BufferedReader(new InputStreamReader(
					clientSocket.getInputStream()));
			outToServer = new DataOutputStream(clientSocket.getOutputStream());
		} catch (IOException e) {
			System.out.println("Failed to connect server " + remoteHost + ":"
					+ remotePort);
			System.out.println(e.toString());
			e.printStackTrace();
		}
		// start the client's thread
		start();
		
		/*
		 * handle client command line argument 
		 */
		
		log.info("USERNAME => "+Settings.getUsername());
		//Client wants to login
		if (!Settings.getUsername().equals("anonymous") && !Settings.getSecret().equals("")){
			JSONObject loginObject = new JSONObject();
			loginObject.put("command", "LOGIN");
			loginObject.put("username", Settings.getUsername());
			loginObject.put("secret", Settings.getSecret());
			this.sendObject(loginObject);
		}else if (!Settings.getUsername().equals("anonymous") && Settings.getSecret().equals("")){
			//client wants to register
			String secret=Settings.nextSecret();
			Settings.setSecret(secret);
			JSONObject registerObject = new JSONObject();
			registerObject.put("command", "REGISTER");
			registerObject.put("username", Settings.getUsername());
			//generate a secret key
			Settings.setSecret(Settings.nextSecret());
			
			registerObject.put("secret", Settings.getSecret());
			this.sendObject(registerObject);
				
		}else if(Settings.getUsername().equals("anonymous") && Settings.getSecret().equals("")){
			JSONObject loginObject = new JSONObject();
			loginObject.put("command", "LOGIN");
			loginObject.put("username", Settings.getUsername());
			loginObject.put("secret", Settings.getSecret());
			this.sendObject(loginObject);
		}
	}

	// called by the gui when the user clicks "send"
	@SuppressWarnings("unchecked")
	public void sendActivityObject(JSONObject activityObj) {
		String JsonString = activityObj.toJSONString();
		
		JSONObject activity = new JSONObject();
		activity.put("command", "ACTIVITY_MESSAGE");
		activity.put("username",Settings.getUsername());
		activity.put("secret", Settings.getSecret());
		activity.put("activity", JsonString);
		
		try {
			outToServer.writeBytes(activity.toJSONString() + '\n');
			System.out.println("Msg sent");
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void sendObject(JSONObject activityObj) {
		String JsonString = activityObj.toJSONString();
		try {
			outToServer.writeBytes(JsonString + '\n');
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Msg sent");
	}

	// called by the gui when the user clicks disconnect
	public void disconnect() {
		/*
		 * other things to do
		 */
		setTerm(true);
		JSONObject logout = new JSONObject();
		logout.put("command","LOGOUT");
		this.sendObject(logout);
		this.closeConnection();
		
	}

	// the client's run method, to receive messages
	@SuppressWarnings("unchecked")
	@Override
	public void run() {
		while (!term) {
			try {
				String JsonMsg = inFromServer.readLine();
				if(JsonMsg!=null){
				JSONObject obj;
				JSONParser parser = new JSONParser();
				obj = (JSONObject) parser.parse(JsonMsg);
				textFrame.setOutputText(obj);
				
				if(obj.get("command").equals("REDIRECT")){
					this.clientSocket = new Socket(obj.get("hostname").toString(), Integer.parseInt(obj.get("port").toString()));
					this.inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
					this.outToServer = new DataOutputStream(clientSocket.getOutputStream());
					log.info("---Established new redirect connection---");

					
					JSONObject login = new JSONObject();
					
					login.put("command", "LOGIN");
					login.put("username", Settings.getUsername());
					login.put("secret", Settings.getSecret());
					
					this.sendObject(login);
					//log.info("---sent activity object---");
					
					
				}
				
				if(obj.get("command").equals("REGISTER_SUCCESS")){
					
					JSONObject login = new JSONObject();
					login.put("command", "LOGIN");
					login.put("username", Settings.getUsername());
					login.put("secret", Settings.getSecret());
					this.sendObject(login);
					
				}
				if(obj.get("command").equals("LOGIN_FAILED")){
					this.closeConnection();
				}
				if(obj.get("command").equals("REGISTER_FAILED")){
					this.closeConnection();
				}
				}

			} catch (IOException | ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	/*
	 * additional methods
	 */
	public void closeConnection(){
		textFrame.setVisible(false);
		try {
			setTerm(true);
			inFromServer.close();
			outToServer.close();
			//clientSocket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public final void setTerm(boolean t){
		term = t;
	}
}
