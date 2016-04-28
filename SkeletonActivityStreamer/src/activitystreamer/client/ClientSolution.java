package activitystreamer.client;

//just some modify to check if I can push on git
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
	}

	// called by the gui when the user clicks "send"
	public void sendActivityObject(JSONObject activityObj) {
		String JsonString = activityObj.toJSONString();

		try {
			outToServer.writeBytes(JsonString + '\n');
			System.out.println("Msg sent");
			
			if(activityObj.get("command").equals("LOGOUT")){
				textFrame.setVisible(false);
			}
			//save secret key to Settings
			if(activityObj.containsKey("secret")){
				Settings.setSecret(activityObj.get("secret").toString());
			}
			//save user name to Settings
			if(activityObj.containsKey("username")){
				Settings.setUsername(activityObj.get("username").toString());
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// called by the gui when the user clicks disconnect
	public void disconnect() {
		textFrame.setVisible(false);
		/*
		 * other things to do
		 */
		setTerm(true);
		JSONObject logout = new JSONObject();
		logout.put("command","LOGOUT");
		this.sendActivityObject(logout);
		
		
		/*try {
			setTerm(true);
			clientSocket.close();
			System.out.println("Connection closed.");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
	}

	// the client's run method, to receive messages
	@SuppressWarnings("unchecked")
	@Override
	public void run() {
		while (!term) {
			try {
				String JsonMsg = inFromServer.readLine();
				JSONObject obj;
				JSONParser parser = new JSONParser();
				obj = (JSONObject) parser.parse(JsonMsg);
				textFrame.setOutputText(obj);
				
				if(obj.get("command").equals("REDIRECT")){
					Socket clientSocket = new Socket(obj.get("hostname").toString(), Integer.parseInt(obj.get("port").toString()));
					inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
					outToServer = new DataOutputStream(clientSocket.getOutputStream());
					log.info("***Established new redirect connection***");

					
					JSONObject login = new JSONObject();
					
					login.put("command", "LOGIN");
					login.put("username", Settings.getUsername());
					login.put("secret", Settings.getSecret());
					
					this.sendActivityObject(login);
					log.info("**sent activity object**");
					
					
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
	public final void setTerm(boolean t){
		term = t;
	}
}
