package edu.serg.tshib;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorFactoryBean;

public class IntegrityProviderDataConnectorFactoryBean extends
		BaseDataConnectorFactoryBean {

	private String vsUrl;

	@Override
	protected Object createInstance() throws Exception {
		IntegrityProviderDataConnector connector = new IntegrityProviderDataConnector(
				getVsUrl());
		populateDataConnector(connector);
		return connector;

	}

	@Override
	public Class getObjectType() {
		return IntegrityProviderDataConnector.class;
	}

	/**
	 * @param vsUrl
	 *            the vsUrl to set
	 */
	public void setVsUrl(String vsUrl) {
		this.vsUrl = vsUrl;
	}

	/**
	 * @return the vsUrl
	 */
	public String getVsUrl() {
		return vsUrl;
	}

}
