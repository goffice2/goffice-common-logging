package net.gvcc.goffice.logger;

import java.util.Map;

/**
 * <p>
 * The <code>EvaluateOption</code> class contains the allowed values about the configuration of each keycloak security context attributes managed by
 * <code>net.gvcc.goffice.logger.GOfficeJsonLayout</code>. <br />
 * You can use this values into the logback.xml. <br />
 * For more information, see the logback.xml file you can find in the main/resources directory. <br />
 * The default value for each attribute is "auth-only" which means that the value will be printd to the stream only if session is authenticated.
 * </p>
 * 
 * <p>
 * Data:Jun 17,2022*
 * </p>
 * 
 * @author <a href="mailto:renzo.poli@sidera.it">Renzo Poli</a>
 * 
 * @version 2.0.3
 */
public enum EvaluateOption {

	/**
	 * as config attribute: "true"
	 */
	TRUE,
	/**
	 * as config attribute: "false"
	 */
	FALSE,
	/**
	 * as config attribute:"auth-only"
	 */
	AUTH_ONLY;

	/**
	 * Converts the enum value as attribute value (e.g: AUTH_ONLY -> "auth-only")
	 */
	@Override
	public String toString() {
		return name().toLowerCase().replaceFirst("_", "-");
	}

	/**
	 * Evaluate the string value as managed in logback.xml, returning the real enumeration value (e.g: "auth-only" -> AUTH_ONLY ). <br />
	 * If error was encountered, the exception or message will be stored into the <code>configErrors</code> map, so it will be printed to the output stream by the log context.
	 * 
	 * @param label
	 *            the key used to store che enumeration into the third parameter configErrors
	 * @param value
	 *            the string to be evaluated
	 * @param configErrors
	 *            The map used to store che configuration
	 * @return the enumeration object corresponding to the string value
	 */
	public static EvaluateOption parse(String label, String value, Map<String, Exception> configErrors) {
		EvaluateOption result = AUTH_ONLY; // default value

		if (value != null) {
			try {
				result = EvaluateOption.valueOf(value.toUpperCase().replaceFirst("-", "_"));
			} catch (IllegalArgumentException e) {
				synchronized (configErrors) {
					configErrors.put(label, new IllegalArgumentException("an invalid value was specified: ".concat(value)));
				}
			} catch (Exception e) {
				synchronized (configErrors) {
					configErrors.put(label, e);
				}
			}
		}

		return result;
	}
}
