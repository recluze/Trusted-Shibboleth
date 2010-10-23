package edu.serg.tshib;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class IntegrityProviderDataConnectorNamespaceHandler extends
		BaseSpringNamespaceHandler {

	public static String NAMESPACE = "urn:serg.edu:shibboleth:2.0:resolver";

	@Override
	public void init() {
		registerBeanDefinitionParser(
				IntegrityProviderDataConnectorBeanDefinitionParser.QNAME,
				new IntegrityProviderDataConnectorBeanDefinitionParser());
	}

}
