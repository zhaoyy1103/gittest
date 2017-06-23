package com.watchdata.test.gp;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.watchdata.commons.lang.WDStringUtil;

/**
 * CommonTool.java
 * 
 * @description:
 * 
 * @author: zhaoguo.wang Feb 2, 2012
 * 
 * @version: 1.0.0
 * 
 * @modify:
 * 
 * @Copyright: watchdata
 */
public class CommonTool {

	/**
	 * 将int转换为长度为1字节�?byte
	 */
	public static byte[] intToByte(int i) {
		return longToBytes(i, 1);
	}

	/**
	 * 将int转换为长度为2字节�?byte[]
	 */
	public static byte[] intToBytes2(int i) {
		return longToBytes(i, 2);
	}

	/**
	 * 将int转换为长度为3字节�?byte[]
	 */
	public static byte[] intToBytes3(int i) {
		return longToBytes(i, 3);
	}

	/**
	 * 将int转换为长度为4字节�?byte[]
	 */
	public static byte[] intToBytes4(int i) {
		return longToBytes(i, 4);
	}

	public static byte[] longToBytes5(long i) {
		return longToBytes(i, 5);
	}

	/**
	 * 返回�?��byte数组，把�?��int转换成为�?��指定长度的数�?
	 * 
	 * @param num
	 *            int
	 * @param len
	 *            int
	 * @return byte[]
	 */
	public static byte[] longToBytes(long num, int len) {
		byte[] data = new byte[len];
		for (int i = len - 1; i >= 0; i--) {
			data[i] = (byte) (num & 0xFF);
			num = num >> 8;
		}

		return data;
	}

	/**
	 * 返回�?��int,把一个转换为�?��int
	 * 
	 * @param data
	 *            byte[]
	 * @return int
	 */
	public static int bytesToInt(byte[] data) {
		int num = 0;
		for (int i = 0; i < data.length; i++) {
			num = (num << 8) | (data[i] & 0xFF);
		}

		return num;
	}

	/**
	 * get an int value from a byte array
	 * 
	 * @param data
	 *            the byte array
	 * @param offset
	 *            a starting offset into the byte array
	 * @return the int (32-bit) value
	 */
	public static int getInt(byte[] data, int offset) {
		int i = offset;
		int b0 = data[i++] & 0xFF;
		int b1 = data[i++] & 0xFF;
		int b2 = data[i++] & 0xFF;
		int b3 = data[i++] & 0xFF;
		return (b0 << 24) + (b1 << 16) + (b2 << 8) + (b3 << 0);
	}

	private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
	private static Random random = new Random();
	private static int i = 0;

	public static String getSessionID() {

		if (i >= 90)
			i = 0;

		StringBuffer sb = new StringBuffer();
		sb.append(dateFormat.format(new Date()));
		sb.append(WDStringUtil.paddingHeadZero("" + i++, 2));
		sb.append(WDStringUtil.paddingHeadZero("" + random.nextInt(9999), 4));

		return sb.toString();

	}
	
	public static String getCurrentDateString(){
		return dateFormat.format(new Date());
	}
	public static String getHexLen(String str, int lenSize) {

		if (null==str||"".equals(str)) {
			return "00";
		}
		// String len = "" + Integer.toString((str.length() / 2), 16);
		int len = str.length() / 2;
		String le = Integer.toString(len, 16);
		
		if (!checkStringIsEven(le)) {
			le = "0" + le;
		}
		return le;

	}
	/**
	 * chenck the str is even if the str is enve then return true otherwise
	 * return false;
	 * 
	 * @param str
	 * @return
	 */
	public static boolean checkStringIsEven(String str) {
		if (str.length() % 2 == 0) {
			return true;
		} else {
			return false;
		}
	}
}
