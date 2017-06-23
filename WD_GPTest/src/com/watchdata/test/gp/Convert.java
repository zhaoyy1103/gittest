package com.watchdata.test.gp;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public abstract class Convert
{
	private static Log LOGGER = LogFactory.getLog(Convert.class);

	/**
	 * 日期转换�?
	 * 
	 * @param date
	 *            字符串日�?
	 * @param format
	 *            日期格式：yyyy-MM-dd HH:mm:ss
	 * @return 日期
	 */
	public static Date convertStringToDate(String date, String format)
	{
		Date dateResult = null;
		SimpleDateFormat formatResult = new SimpleDateFormat(format);
		if (date != null && !date.equals(""))
		{
			try
			{
				dateResult = formatResult.parse(date);
			} catch (ParseException e)
			{
				LOGGER.error("Date convert error:" + e.getMessage());
			}
		}
		return dateResult;
	}

	/**
	 * 日期转换�?
	 * 
	 * @param date
	 *            日期
	 * @param format
	 *            日期格式：yyyy-MM-dd HH:mm:ss
	 * @return 日期字符�?
	 */
	public static String convertDateToString(Date date, String format)
	{
		String dateResult = null;
		SimpleDateFormat formatResult = new SimpleDateFormat(format);
		if (date != null)
		{
			dateResult = formatResult.format(date);
		}
		return dateResult;
	}

	/**
	 * String to Long 转换�?
	 * 
	 * @param str
	 *            要转换的字符�?
	 * @return Long 结果
	 */
	public static Long StringToLong(String str)
	{
		Long result = null;
		if (null != str && !"".equals(str.trim()))
		{
			try
			{
				result = Long.parseLong(str.trim());
			} catch (Exception e)
			{
				LOGGER.error("string to long convert error:" + e.getMessage());
			}
		}
		return result;
	}

	/**
	 * String to Integer 转换�?
	 * 
	 * @param str
	 *            要转换的字符�?
	 * @return Integer 结果
	 */
	public static Integer StringToInteger(String str)
	{
		Integer result = null;
		if (null != str && !"".equals(str.trim()))
		{

			try
			{
				result = Integer.parseInt(str.trim());
			} catch (Exception e)
			{
				LOGGER.error("string to int convert error:" + e.getMessage());
			}
		}
		return result;
	}
	
	private static byte charToByte(char c)
	{
		return (byte) "0123456789ABCDEF".indexOf(c);
	}
	
	/**
	 * 十六进制字符串转成byte数组
	 * @param hexString
	 * @return
	 */
	public static byte[] stringToHexBytes(String hexString)
	{
		if (hexString == null || hexString.equals(""))
		{
			return null;
		}
		hexString = hexString.toUpperCase();
		int length = hexString.length() / 2;
		if (length == 0)
		{
			hexString = "0" + hexString;
			length = 1;
		}
		char[] hexChars = hexString.toCharArray();
		byte[] d = new byte[length];
		for (int i = 0; i < length; i++)
		{
			int pos = i * 2;
			d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
		}
		return d;
	}
	
	/**
	 * 将字节转换成16进制字符串，e.g.：bytesToHexString(0x0A) = "0A"
	 * 
	 * @param bArray
	 * @return
	 */
	public static final String bytesToHexString(byte[] bArray)
	{
		return bytesToHexString(bArray, 0, bArray.length);
	}

	/**
	 * 将bArray数组中下标为begin，长度为length的字节数据段，转换成16进制字符�?
	 * 
	 * @param bArray
	 * @param begin
	 * @param length
	 * @return
	 */
	public static final String bytesToHexString(byte[] bArray, int begin,
	        int length)
	{
		StringBuffer sb = new StringBuffer(length);
		String sTemp;
		for (int i = begin; i < begin + length; i++)
		{
			sTemp = Integer.toHexString(0xFF & bArray[i]);
			if (sTemp.length() < 2)
				sb.append(0);
			sb.append(sTemp.toUpperCase());
		}
		return sb.toString();
	}

	/**
	 * 
	 * @param bArray
	 * @return
	 */
	public static final String bytesToBCDString(byte[] bArray)
	{
		return bytesToBCDString(bArray, 0, bArray.length);
	}

	/**
	 * 
	 * @param bArray
	 * @param begin
	 * @param length
	 * @return
	 */
	public static final String bytesToBCDString(byte[] bArray, int begin,
	        int length)
	{
		StringBuffer sb = new StringBuffer(length);
		String sTemp;
		for (int i = begin; i < begin + length; i++)
		{
			sTemp = Integer.toHexString(0xFF & bArray[i]);
			if (sTemp.length() < 2)
				sb.append(0);
			sb.append(sTemp.toUpperCase());
		}
		int index = sb.indexOf("F");
		sTemp = sb.toString();
		if (index >= 0)
		{
			sTemp = sb.substring(0, index);
		}

		return sTemp;
	}

	/**
	 * 字节码转换成16进制字符�?
	 * 
	 * @param b
	 * @return
	 */
	public static String byte2hex(byte b)
	{
		StringBuffer retString = new StringBuffer();
		retString.append(Integer.toHexString(0x0100 + (b & 0x00FF))
		        .substring(1).toUpperCase());
		return retString.toString();
	}

	/**
	 * 字节码转换成16进制字符�?
	 * 
	 * @param bytes
	 * @return
	 */
	public static String byte2hex(byte bytes[])
	{
		StringBuffer retString = new StringBuffer();
		for (int i = 0; i < bytes.length; ++i)
		{
			retString.append(Integer.toHexString(0x0100 + (bytes[i] & 0x00FF))
			        .substring(1).toUpperCase());
		}
		return retString.toString();
	}

	/**
	 * 将十六进制转换为标准的字节码
	 * 
	 * @param b
	 * @return
	 */
	public static byte[] hex2byte(byte[] b)
	{
		if ((b.length % 2) != 0)
			throw new IllegalArgumentException("长度不是偶数");
		byte[] b2 = new byte[b.length / 2];
		for (int n = 0; n < b.length; n += 2)
		{
			String item = new String(b, n, 2);
			b2[n / 2] = (byte) Integer.parseInt(item, 16);
		}
		return b2;
	}

	/**
	 * 将byte[]转换成int
	 * 
	 */
	public static final int bytesToInt(byte[] bArray)
	{
		return bytesToInt(bArray, 0, bArray.length);
	}

	/**
	 * 将byte[]转换成int
	 * 
	 */
	public static final int bytesToInt(byte[] bArray, int begin, int length)
	{
		int totalLength = 0;
		for (int i = begin; i < begin + length; i++)
		{
			totalLength += (bArray[i] & 0xff) << ((length + begin - i - 1) * 8);
		}
		return totalLength;
	}

	/**
	 * �?int 转换成byte[]
	 * 
	 * @param num
	 *            :要转换的int数据
	 * @param length
	 *            :转换成为多大的字节数�?，length 不能超过4
	 */
	public static final byte[] intToBytes(int num, int length)
	        throws RuntimeException
	{
		if (length > 4)
		{
			throw new RuntimeException("Int length can't over 4 bytes");
		}
		byte[] conv = new byte[length];
		for (int i = 0; i < length; i++)
		{
			conv[i] = (byte) ((num >>> ((conv.length - 1 - i) * 8)) & 0xff);
		}
		return conv;
	}
	
	/**
	 * 每两个字节中位置进行交换
	 * b[0] = b[1]
	 * b[1] = b[0]
	 * @param b
	 * @return
	 */
	public static byte[] convertByte(byte[] b)
	{
		//设备返回的数据每两个自己颠�?，需要转�?		
		byte tmp;
		for(int j = 0; j < b.length; )
		{
			if((j+1) >= b.length)
			{
				break;
			}
			tmp = b[j];
			b[j] = b[j+1];
			b[j+1] = tmp;        	
			j+=2;
		}	
		return b;
	}
}
