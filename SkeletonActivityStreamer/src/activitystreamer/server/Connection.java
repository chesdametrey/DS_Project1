package activitystreamer.server;


import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
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
import activitystreamer.util.Settings;


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
		
		log.info("--- Message to send :"+msg);
		byte[] text = msg.getBytes();

		PublicKey pubkey=ControlSolution.parentPubKey;
		boolean result = false;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			 cipher.init(Cipher.ENCRYPT_MODE, pubkey);
			 byte[] encryptedText=cipher.doFinal(text);
			//String encryptedStr=byteToString(encryptedText);
			 String encryptedHex=byteToHex(encryptedText);
			 log.info("--- Encrypted Message : "+ encryptedHex);
			 log.info("=== Sent Encrypted Message (Public Key) ===");
			 result=writeMsg(encryptedHex);
			 
		} catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}
	
	public boolean writeMsgWithSharedkey(String msg) {
		
		byte[] text=msg.getBytes();
		SecretKey sharedkey=ControlSolution.sharedKeyList.get(this);
		boolean result = false;
		try {
			 Cipher cipher = Cipher.getInstance("DES");
			 cipher.init(Cipher.ENCRYPT_MODE, sharedkey);
			 byte[] encryptedText=cipher.doFinal(text);
			 
			 String hex = byteToHex(encryptedText);
			 log.info("--- Message Encrypted With SharedKey ---");
			 log.info("--- Encrypted Message : "+hex);
			 log.info("=== Sent Encrypted Message (Shared Key) ===");
			 result=writeMsg(hex);

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
	/*public String byteToString(byte[] b){
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
	}*/
	
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
