package activitystreamer.client;

import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

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
import activitystreamer.util.Settings;
import sun.misc.BASE64Encoder;

public class ClientSolution extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSolution clientSolution;
	private static boolean term = false;
	private TextFrame textFrame;

	/*
	 * additional variables
	 */
	private Socket clientSocket;
	private BufferedReader inFromServer;
	private DataOutputStream outToServer;
	private String remoteHost = Settings.getRemoteHostname();
	private int remotePort = Settings.getRemotePort();

	PublicKey pubKey;
	SecretKey sharedKey;

	private JSONParser parser = new JSONParser();

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
			System.out.println("Connect to Server " + this.remoteHost + ":" + remotePort + " successfully.");
			inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			outToServer = new DataOutputStream(clientSocket.getOutputStream());
		} catch (IOException e) {
			System.out.println("Failed to connect server " + remoteHost + ":" + remotePort);
			System.out.println(e.toString());
			e.printStackTrace();
		}
		// start the client's thread
		JSONObject requestKey = new JSONObject();
		requestKey.put("command", "REQUEST_PUBKEY");
		this.sendObject(requestKey);

		start();
	}

	// called by the gui when the user clicks "send"
	@SuppressWarnings("unchecked")
	public void sendActivityObject(JSONObject activityObj) {
		String JsonString = activityObj.toJSONString();

		JSONObject activity = new JSONObject();
		activity.put("command", "ACTIVITY_MESSAGE");
		activity.put("username", Settings.getUsername());
		activity.put("secret", Settings.getSecret());
		activity.put("activity", JsonString);

//		try {
//			outToServer.writeBytes(activity.toJSONString() + '\n');
//			System.out.println("Msg sent");
//
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		sendObjectWithSharedKey(activity);
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
	public void sendObjectWithPubKey(JSONObject activityObj){
		String JsonString = activityObj.toJSONString();
		 byte[] text = JsonString.getBytes();
		 try {
				Cipher cipher = Cipher.getInstance("RSA");
				 cipher.init(Cipher.ENCRYPT_MODE, pubKey);
				 byte[] encryptedText=cipher.doFinal(text);
				
				//String encryptedStr=byteToString(encryptedText);
				 String encryptedHex=byteToHex(encryptedText);
				 log.info("--Encrypted Message : "+ encryptedHex);
				 log.info("--Sent Encrypted Message---");
				 //result=writeMsg(encryptedHex);
				 outToServer.writeBytes(encryptedHex + '\n');		
				 //log.info("msg!!!!!"+new String(encryptedText));
				 //log.info("msg + hex"+new String(encryptedHex));
				 
			} catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}

	public void sendObjectWithSharedKey(JSONObject activityObj) {
		String JsonString = activityObj.toJSONString();
		byte[] text = JsonString.getBytes();

		try {
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, sharedKey);
			byte[] encryptedText = cipher.doFinal(text);

			String hex = byteToHex(encryptedText);

			//log.info("***TEST-encrypt***:" + new String(encryptedText));

			// byte[] encode = decode.getBytes(UTF8_CHARSET);
			log.info("--- Encrypted Message:" + hex);
			log.info("--- Sent Encypted Message ---");

			// byte[] b = new BigInteger(hexString.toString(),16).toByteArray();
			// result=writeMsg(hex);
			outToServer.writeBytes(hex + '\n');
		} catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException
				| NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// try {
		// outToServer.writeBytes(hex + '\n');
		// } catch (IOException e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// }
		System.out.println("Msg sent");
	}

	// called by the gui when the user clicks disconnect
	@SuppressWarnings("unchecked")
	public void disconnect() {
		/*
		 * other things to do
		 */
		setTerm(true);
		JSONObject logout = new JSONObject();
		logout.put("command", "LOGOUT");
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
				if (JsonMsg != null) {
					log.info("--- JSON Validation = " + isGoodJson(JsonMsg));
					if (!isGoodJson(JsonMsg)) {
						log.info("=========");
						// if(con.newVersion==false)
						// con.newVersion=true;
						JsonMsg = decrypt(JsonMsg);
					}
					JSONObject obj;
					JSONParser parser = new JSONParser();
					obj = (JSONObject) parser.parse(JsonMsg);
					textFrame.setOutputText(obj);

					if (obj.get("command").equals("REDIRECT")) {
						this.clientSocket = new Socket(obj.get("hostname").toString(),
								Integer.parseInt(obj.get("port").toString()));
						this.inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
						this.outToServer = new DataOutputStream(clientSocket.getOutputStream());
						log.info("***Established new redirect connection***");

						JSONObject login = new JSONObject();

						login.put("command", "LOGIN");
						login.put("username", Settings.getUsername());
						login.put("secret", Settings.getSecret());

						this.sendObjectWithSharedKey(login);
						log.info("**sent activity object**");

					}

					if (obj.get("command").equals("REGISTER_SUCCESS")) {

						JSONObject login = new JSONObject();
						login.put("command", "LOGIN");
						login.put("username", Settings.getUsername());
						login.put("secret", Settings.getSecret());
						this.sendObjectWithSharedKey(login);

					}
					if (obj.get("command").equals("LOGIN_FAILED")) {
						this.closeConnection();
					}
					if (obj.get("command").equals("REGISTER_FAILED")) {
						this.closeConnection();
					}
					if (obj.get("command").equals("RESPONSE_PUBKEY")) {
						String pubKeyString = (String) obj.get("pubkey");
						pubKey = stringToPublicKey(pubKeyString);
						// generate shared key for this connection
						try {
							KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
							sharedKey = keyGenerator.generateKey();

							log.info("USERNAME => " + Settings.getUsername());
							// Client wants to login
							if (!Settings.getUsername().equals("anonymous") && !Settings.getSecret().equals("")) {
								JSONObject loginObject = new JSONObject();
								loginObject.put("command", "LOGIN");
								loginObject.put("username", Settings.getUsername());
								loginObject.put("secret", Settings.getSecret());
								loginObject.put("sharedkey", secretKeyToString(sharedKey));
								this.sendObjectWithPubKey(loginObject);
							} else if (!Settings.getUsername().equals("anonymous") && Settings.getSecret().equals("")) {
								// client wants to register
								JSONObject registerObject = new JSONObject();
								registerObject.put("command", "REGISTER");
								registerObject.put("username", Settings.getUsername());
								// generate a secret key
								Settings.setSecret(Settings.nextSecret());

								registerObject.put("secret", Settings.getSecret());
								registerObject.put("sharedkey", secretKeyToString(sharedKey));
								this.sendObjectWithPubKey(registerObject);

							} else if (Settings.getUsername().equals("anonymous") && Settings.getSecret().equals("")) {
								JSONObject loginObject = new JSONObject();
								loginObject.put("command", "LOGIN");
								loginObject.put("username", Settings.getUsername());
								loginObject.put("secret", Settings.getSecret());
								loginObject.put("sharedkey", secretKeyToString(sharedKey));
								this.sendObjectWithPubKey(loginObject);
							}

						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
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
	public void closeConnection() {
		textFrame.setVisible(false);
		try {
			setTerm(true);
			inFromServer.close();
			outToServer.close();
			// clientSocket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public final void setTerm(boolean t) {
		term = t;
	}

	public String secretKeyToString(SecretKey k) {
		String encodedKey = Base64.getEncoder().encodeToString(k.getEncoded());
		return encodedKey;
	}

	public boolean isGoodJson(String json) {
		@SuppressWarnings("unused")
		JSONObject obj;
		try {
			obj = (JSONObject) parser.parse(json);
			// ClientSolution.getInstance().sendActivityObject(obj);
			return true;
		} catch (ParseException e1) {
			log.error("invalid JSON object entered into input text field, data not sent");
			return false;
		}

	}

	public String decrypt(String msg) {

		// byte[] receivedMsg=stringToByte(msg);
		// byte[] b = new BigInteger(msg.toString(),16).toByteArray();
		HexBinaryAdapter adapter = new HexBinaryAdapter();
		byte[] b = adapter.unmarshal(msg);

		// byte[] encode = stringToByte(msg);
		log.info("== Client == Message Decrypted with Hex :" + new String(b));
		// byte[] receivedMsg=msg.getBytes();

		byte[] text = null;

		// decrypt with sharedkey
		try {
			Cipher desCipher = Cipher.getInstance("DES");
			desCipher.init(Cipher.DECRYPT_MODE, sharedKey);
			text = desCipher.doFinal(b);
			log.info("--- Message Decrypted with SharedKey: " + new String(text));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// String jsonStr=new sun.misc.BASE64Encoder().encodeBuffer(text);
		// String jsonStr=byteToString(text);
		String jsonStr = new String(text);
		return jsonStr;
	}

	public String byteToHex(byte[] b) {
		StringBuilder hexString = new StringBuilder();
		for (int i = 0; i < b.length; i++) {
			String hex = Integer.toHexString(0xFF & b[i]);
			if (hex.length() == 1) {
				hexString.append('0');
			}
			hexString.append(hex);
		}

		return hexString.toString();
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

}
