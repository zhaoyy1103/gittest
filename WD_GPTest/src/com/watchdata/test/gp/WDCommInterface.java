package com.watchdata.test.gp;


public class WDCommInterface {
	private static byte charToByte(char c) {
		return (byte) "0123456789ABCDEF".indexOf(c);
	}
	public static int unsignedByteToInt(byte b) {  
        return (int) b & 0xFF;  
    }  
	public static String inttoString(int i)
	{
		return String.valueOf(i);
	}
	public  static int bytetoint(byte[] data, int offset) {
		int num = 0;
		for (int i = offset; i < offset + 4; i++) {
			num <<= 8;
			num |= (data[i] & 0xff);
		}
		return num;
	}
	public static byte[] shortToBytes(short num) {
	byte[] b = new byte[2];
	for (int i = 0; i < 2; i++) {
		b[i] = (byte) (num >>> (i * 8));

	}
	return b;
}
	public static byte[]inttobyte(int i)
	{
		byte[] a = new byte[4];
        a[0] = (byte) (0xff & i);
        a[1] = (byte) ((0xff00 & i) >> 8);
        a[2] = (byte) ((0xff0000 & i) >> 16);
        a[3] = (byte) ((0xff000000 & i) >> 24);
        return a;
	}
	public static byte[]inttobyteEx(int i)
	{
	byte[] a = new byte[4];
	        a[0] = (byte) ((0xff000000 & i) >> 24);
	        a[1] = (byte) ((0xff0000 & i) >> 16);
	        a[2] = (byte) ((0xff00 & i) >> 8);
	        a[3] = (byte) (0xff & i);
	        return a;
	}



	 public static short byteToShort(byte[] b) { 
	        short s = 0; 
	        short s0 = (short) (b[0] & 0xff);// ����? 
	        short s1 = (short) (b[1] & 0xff); 
	        s1 <<= 8; 
	        s = (short) (s0 | s1); 
	        return s; 
	    }



public static String printHexStringlen( byte[] b,long len) { 
  	  String result="";
  	  for (int i = 0; i < len; i++)
  	  { 
  	       String hex = Integer.toHexString(b[i] & 0xFF); 
  	       if (hex.length() == 1) { 
  	         hex = '0' + hex; 
  	       } 
  	       result=result+hex.toUpperCase(); 
  	  } 
  	  return result;

 }
public static String Bytes2HEX(byte[] bytes, int start, int offset) {
	if (bytes != null) {
		StringBuffer sb = new StringBuffer();
		for (int i = start; i < start + offset; i++) {
			sb.append(HEX[bytes[i] >> 4 & 0x0f]);
			sb.append(HEX[bytes[i] & 0x0f]);
		}
		return sb.toString();
	} else
		throw new IllegalArgumentException("data is null");
}

public static byte[] stringToHexBytes(String hexString) {
	if (hexString == null || hexString.equals("")) {
		return null;
	}
	hexString = hexString.toUpperCase();
	int length = hexString.length() / 2;
	if (length == 0) {
		hexString = "0" + hexString;
		length = 1;
	}
	char[] hexChars = hexString.toCharArray();
	byte[] d = new byte[length];
	for (int i = 0; i < length; i++) {
		int pos = i * 2;
		d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
	}
	return d;
}
public static  char[] HEX = { '0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
}
