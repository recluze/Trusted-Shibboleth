package org.csrdu.tshib;

import javax.xml.namespace.QName;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorBeanDefinitionParser;

public class IntegrityProviderDataConnectorBeanDefinitionParser extends
		BaseDataConnectorBeanDefinitionParser {

	public static final QName QNAME = new QName(
			IntegrityProviderDataConnectorNamespaceHandler.NAMESPACE,
			"IntegrityProviderLookup");

	protected Class getBeanClass(Element element) {
		return IntegrityProviderDataConnectorFactoryBean.class;
	}

	protected void doParse(Element element, BeanDefinitionBuilder builder) {
		super.doParse(element, builder);
		String vsUrl = element.getAttributeNS(null, "vsUrl");
		builder.addPropertyValue("vsUrl", vsUrl);
	}
}
