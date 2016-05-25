package activitystreamer.server;


import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;

import activitystreamer.util.Settings;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


public class Connection extends Thread {
	private static final Logger log = LogManager.getLogger();
	private DataInputStream in;
	private DataOutputStream out;
	private BufferedReader inreader;
	private PrintWriter outwriter;
	private boolean open = false;
	private Socket socket;
	private boolean term=false;
	
	boolean newVersion=false;
	
	Connection(Socket socket) throws IOException{
		in = new DataInputStream(socket.getInputStream());
	    out = new DataOutputStream(socket.getOutputStream());
	    inreader = new BufferedReader( new InputStreamReader(in));
	    outwriter = new PrintWriter(out, true);
	    this.socket = socket;
	    open = true;
	    start();
	}
	
	/*
	 * returns true if the message was written, otherwise false
	 */
	public boolean writeMsg(String msg) {
		if(open){
			outwriter.println(msg);
			outwriter.flush();
			return true;	
		}
		return false;
	}
	public boolean writeMsgWithPubkey(String msg) {
		 log.info("msg to write:"+msg);
		byte[] text = stringToByte(msg);

		

		PublicKey pubkey=ControlSolution.parentPubKey;
		//log.info("aaapubKey:"+pubkey.toString());
		boolean result = false;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			 cipher.init(Cipher.ENCRYPT_MODE, pubkey);
			 byte[] encryptedText=cipher.doFinal(text);
			
			//String encryptedStr=byteToString(encryptedText);
			 String encryptedStr=byteToHex(encryptedText);
			//JSONObject j=new JSONObject();
			//j.put("encrpte", encryptedStr);
			 result=writeMsg(encryptedStr);
			 log.info("msg!!!!!"+encryptedStr);
		} catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}
	public boolean writeMsgWithSharedkey(String msg) {
		//byte[] text=stringToByte(msg);
		byte[] text=msg.getBytes();
		log.info("***TEST!***:"+new String(text));
		SecretKey sharedkey=ControlSolution.sharedKeyList.get(this);
		log.info("*****encrypt shared key: "+ sharedkey);
		boolean result = false;
		try {
			 Cipher cipher = Cipher.getInstance("DES");
			 cipher.init(Cipher.ENCRYPT_MODE, sharedkey);
			 byte[] encryptedText=cipher.doFinal(text);
			// String str=byteToString(encryptedText);
			 String str=new String(encryptedText);
			 
			 //****CHESDA****

			 String hex = byteToHex(encryptedText);
			 

			  //***CHESDA
			   //change str -> hex
			//String s = byteToString(encryptedText);
			 
			 log.info("***TEST-encrypt***:"+ new String(encryptedText));
			 
			 //byte[] encode = decode.getBytes(UTF8_CHARSET);
			 log.info("***********************TEST-encrypt with HEX***:"+hex);
			 
			 //byte[] b = new BigInteger(hexString.toString(),16).toByteArray();
			 result=writeMsg(hex);
	
			    
			// log.info("***TEST-decrypt with 64***:"+new String(encode));
		} catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return result;
	}
	
	public void closeCon(){
		if(open){
			log.info("closing connection "+Settings.socketAddress(socket));
			try {
				term=true;
				inreader.close();
				out.close();
			} catch (IOException e) {
				// already closed?
				log.error("received exception closing the connection "+Settings.socketAddress(socket)+": "+e);
			}
		}
	}
	
	
	public void run(){
		try {
			String data;
			
			while(!term && (data = inreader.readLine())!=null){
				term=Control.getInstance().process(this,data);
			}
			log.debug("connection closed to "+Settings.socketAddress(socket));
			Control.getInstance().connectionClosed(this);
			in.close();
		} catch (IOException e) {
			log.error("connection "+Settings.socketAddress(socket)+" closed with exception: "+e);
			Control.getInstance().connectionClosed(this);
		}
		open=false;
	}
	
	public Socket getSocket() {
		return socket;
	}
	
	public boolean isOpen() {
		return open;
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
	
	public String byteToHex (byte[] b){
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
	
}
