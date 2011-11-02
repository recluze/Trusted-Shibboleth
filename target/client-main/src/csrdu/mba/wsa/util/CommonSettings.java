/*
 * Copyright (C) 2008 Computer Science Research and Development Unit, 
 * Peshawar, Pakistan.
 * http://csrdu.org/nauman 
 * authors: Nauman (recluze) 
 * Derived from iaik.tc.apps.jtt.common.CommonSettings of jTpmTools from iaik 
 */

package csrdu.mba.wsa.util;

import iaik.tc.tss.api.tspi.TcTssAbstractFactory;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.impl.java.tsp.TcTssLocalCallFactory;
import iaik.tc.utils.logging.Log;

public class CommonSettings {
	private static TcTssAbstractFactory cachedFactory = null;

	public static TcTssAbstractFactory getTssFactory() {
		// only create a new factory if no cache found
		if (cachedFactory == null) {
			try {
				// create a factory
				TcTssAbstractFactory factory = new TcTssLocalCallFactory();

				// get a context object
				TcIContext context = factory.newContextObject();

				// try to connect for testing
				context.connect();
				context.closeContext();

				// cache this factory
				cachedFactory = factory;
			} catch (TcTssException tse) {
				Log.err(tse.getMessage()); // use standard log
			}
		}
		return cachedFactory;
	}
}
