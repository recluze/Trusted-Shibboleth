package edu.serg.tshib;

import java.util.HashMap;
import java.util.Map;

import org.opensaml.ws.transport.http.HTTPInTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.org.apache.xalan.internal.xsltc.runtime.Attributes;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.BaseDataConnector;

import edu.serg.mba.wsa.attserv.AttestationDaemonConnectException;
import edu.serg.mba.wsa.attserv.Client;

public class IntegrityProviderDataConnector extends BaseDataConnector {

	/** VS Url */
	private String vsUrl;

	/** Attestation type: currently only IMA is supported */
	private ATTESTATION_TYPE attestationType;

	/** Authentication type values */
	public static enum ATTESTATION_TYPE {
		IMA
	};

	/** Released Attribute */
	private static final String ATTESTATION_ATTRIBUTE = "PlatformIntegrity";

	private final Logger log = LoggerFactory
			.getLogger(IntegrityProviderDataConnector.class);

	public IntegrityProviderDataConnector(String url) {
		this.setVsUrl(url);
	}

	@Override
	public Map<String, BaseAttribute> resolve(
			ShibbolethResolutionContext resolutionContext)
			throws AttributeResolutionException {

		log.info("Starting validation resolution.");

		Map<String, BaseAttribute> result = new HashMap<String, BaseAttribute>();
		String username = resolutionContext.getAttributeRequestContext()
				.getPrincipalName();
		// add BasicAttributes to the result here.

		log.debug("Creating attributes now.");
		log.debug("Inserting integrity attribute: {}", ATTESTATION_ATTRIBUTE);

		BasicAttribute<String> attribute = new BasicAttribute<String>();
		attribute.setId(ATTESTATION_ATTRIBUTE);

		log.debug("Contacting VS at {}", vsUrl);

		String targetAddr;
		boolean attResult = false;
		try {
			log
					.debug("Sending attestation request to VS for client: {}",
							vsUrl);
			Client attClient = new Client();

			// get the IP of the client
			// String targetAddr =
			// resolutionContext.getAttributeRequestContext()
			// .getPrincipalName();

			HTTPInTransport req = (HTTPInTransport) resolutionContext
					.getAttributeRequestContext().getInboundMessageTransport();
			targetAddr = req.getPeerAddress();
			log.info("Performing attestation of client at: {}", targetAddr);

			attResult = attClient.attestClient(targetAddr);
		} catch (AttestationDaemonConnectException e) {
			log
					.error("Attestation daemon couldn't be contacted. Assuming bad integrity.");
			// throw new Exception(e);
		}
		log.debug("Received attestation response from VS: {}", attResult);

		log.info("Inserting attestation attribute: {}", ATTESTATION_ATTRIBUTE);
		attribute.getValues().add(Boolean.toString(attResult));
		result.put(attribute.getId(), attribute);

		log.info("Returning integrity attributes.");
		return result;

	}

	@Override
	public void validate() throws AttributeResolutionException {
		// TODO Auto-generated method stub

	}

	/**
	 * @param attestationType
	 *            the attestationType to set
	 */
	public void setAttestationType(ATTESTATION_TYPE attestationType) {
		this.attestationType = attestationType;
	}

	/**
	 * @return the attestationType
	 */
	public ATTESTATION_TYPE getAttestationType() {
		return attestationType;
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
