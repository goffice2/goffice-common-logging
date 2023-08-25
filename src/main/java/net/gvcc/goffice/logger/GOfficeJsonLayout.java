/*
 * https://www.goffice.org
 * 
 * Copyright (c) 2005-2022 Consorzio dei Comuni della Provincia di Bolzano Soc. Coop. <https://www.gvcc.net>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package net.gvcc.goffice.logger;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import org.apache.commons.lang3.StringUtils;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.representations.AccessToken;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import ch.qos.logback.classic.spi.ILoggingEvent;

/**
 *
 * <p>
 * The <code>GOfficeJsonLayout</code> class is useful when you need to configure the output by adding some information about keycloak user account. <br />
 * You can print or hide many of data about account, such as: <br />
 * - user.account <br />
 * - user.roles <br />
 * - user.email <br />
 * - other <br />
 * For more information, see the logback.xml file you can find in the main/resources directory.
 * </p>
 * <p>
 * Data: Jun 17, 2022
 * </p>
 * 
 * @author <a href="mailto:renzo.poli@sidera.it">Renzo Poli</a>
 * @version 2.0.3
 */
public class GOfficeJsonLayout extends ch.qos.logback.contrib.json.classic.JsonLayout {

	/**
	 * label of the json attribute
	 */
	public static final String USER_ACCOUNT_ATTR_NAME = "user.account";
	/**
	 * label of the json attribute
	 */
	public static final String USER_ROLES_ATTR_NAME = "user.roles";
	/**
	 * label of the json attribute
	 */
	public static final String USER_REAML_ATTR_NAME = "user.realm";
	/**
	 * label of the json attribute
	 */
	public static final String USER_EMAIL_ATTR_NAME = "user.email";
	/**
	 * label of the json attribute
	 */
	public static final String USER_CLAIMS_ATTR_NAME = "user.claims";

	/**
	 * label of the json attribute which contains the OpenTracing headers
	 */
	// private static final String OPENTRACING_ATTR = "opentracing";

	/**
	 * prefix about headers value
	 */
	private static final String HEADER_ATTR_NAME = "headers";

	/**
	 * print or hide keycloak user account
	 */
	protected EvaluateOption includeUserAccount = EvaluateOption.AUTH_ONLY;
	/**
	 * print or hide keycloak user roles, assigned by Keycloak console
	 */
	protected EvaluateOption includeUserRoles = EvaluateOption.AUTH_ONLY;
	/**
	 * print or hide keycloak user realm currently active
	 */
	protected EvaluateOption includeUserRealm = EvaluateOption.AUTH_ONLY;
	/**
	 * print or hide keycloak user email
	 */
	protected EvaluateOption includeUserEmail = EvaluateOption.AUTH_ONLY;
	/**
	 * print or hide keycloak user claims
	 */
	protected EvaluateOption includeUserClaims = EvaluateOption.AUTH_ONLY;

	/**
	 * print request header values. Use: all or one or more header name as filter.
	 */
	protected String[] includeHeaders = {};

	// ======================================================================================================================================= //

	/**
	 * configuration error temporary storage
	 */
	private Map<String, Exception> configErrors = new HashMap<>();

	// ======================================================================================================================================= //

	/**
	 * Used by context configurator (logback.xml)
	 * 
	 * @param includeUserAccount
	 *            Flag used to log the user account
	 */
	public void setIncludeUserAccount(String includeUserAccount) {
		this.includeUserAccount = EvaluateOption.parse(USER_ACCOUNT_ATTR_NAME, includeUserAccount, configErrors);
	}

	public String getIncludeUserRoles() {
		return includeUserRoles.toString();
	}

	/**
	 * Used by context configurator (logback.xml)
	 * 
	 * @param includeUserRoles
	 *            Flag used to log the user roles
	 */
	public void setIncludeUserRoles(String includeUserRoles) {
		this.includeUserRoles = EvaluateOption.parse(USER_ROLES_ATTR_NAME, includeUserRoles, configErrors);
	}

	public String getIncludeUserRealm() {
		return includeUserRealm.toString();
	}

	/**
	 * Used by context configurator (logback.xml)
	 * 
	 * @param includeUserRealm
	 *            Flag used to log the user realms
	 */
	public void setIncludeUserRealm(String includeUserRealm) {
		this.includeUserRealm = EvaluateOption.parse(USER_REAML_ATTR_NAME, includeUserRealm, configErrors);
	}

	public String getIncludeUserEmail() {
		return includeUserEmail.toString();
	}

	/**
	 * Used by context configurator (logback.xml)
	 * 
	 * @param includeUserEmail
	 *            Flag used to log the user email
	 */
	public void setIncludeUserEmail(String includeUserEmail) {
		this.includeUserEmail = EvaluateOption.parse(USER_EMAIL_ATTR_NAME, includeUserEmail, configErrors);
	}

	public String getIncludeUserClaims() {
		return includeUserClaims.toString();
	}

	/**
	 * Used by context configurator (logback.xml)
	 * 
	 * @param includeUserClaims
	 *            Flag used to log the user claims
	 */
	public void setIncludeUserClaims(String includeUserClaims) {
		this.includeUserClaims = EvaluateOption.parse(USER_CLAIMS_ATTR_NAME, includeUserClaims, configErrors);
	}

	public String[] getIncludeHeaders() {
		return includeHeaders;
	}

	/**
	 * Used by context configurator (logback.xml)
	 * 
	 * @param includeHeaders
	 *            Name of the header, separated by comma, simicolon or spaces, to trace in the log
	 */
	public void setIncludeHeaders(String includeHeaders) {
		this.includeHeaders = StringUtils.trimToEmpty(includeHeaders).split("\\s*[,;\\s]\\s*");
	}

	/*
	 * This method adds the information to the log context so they will be outputted to the stream (console, file, ...) according to the logback.xml configuration
	 * 
	 * @param map the map
	 * 
	 * @param event the event to be logged
	 */
	@Override
	protected void addCustomDataToJsonMap(Map<String, Object> map, ILoggingEvent event) {
		try {
			String userAccount = "<anonymous>";
			String roles = "";
			String realm = "<unknown>";
			String email = "";
			Map<String, Object> claims = null;

			SecurityContext context = SecurityContextHolder.getContext();

			Authentication authentication = context == null ? null : context.getAuthentication();
			if (authentication != null) {
				userAccount = StringUtils.defaultIfBlank(authentication.getName(), userAccount);
				SimpleKeycloakAccount account = (SimpleKeycloakAccount) authentication.getDetails();
				if (account != null) {
					Set<String> accountRoles = account.getRoles();
					if (accountRoles != null) {
						roles = accountRoles.toString();
					}

					KeycloakSecurityContext securityContext = account.getKeycloakSecurityContext();
					if (securityContext != null) {
						realm = StringUtils.defaultString(securityContext.getRealm(), realm);

						AccessToken accessToken = securityContext.getToken();
						if (accessToken != null) {
							email = StringUtils.defaultString(accessToken.getEmail(), email);
							claims = accessToken.getOtherClaims();
						}
					}
				}
			}

			// user-account data
			add(USER_ACCOUNT_ATTR_NAME, asBoolean(this.includeUserAccount, authentication), userAccount, map);
			add(USER_ROLES_ATTR_NAME, asBoolean(this.includeUserRoles, authentication), roles, map);
			add(USER_REAML_ATTR_NAME, asBoolean(this.includeUserRealm, authentication), realm, map);
			add(USER_EMAIL_ATTR_NAME, asBoolean(this.includeUserEmail, authentication), email, map);
			addMap(USER_CLAIMS_ATTR_NAME, asBoolean(this.includeUserClaims, authentication), claims, map);

			// opentracing info
			// addMap(OPENTRACING_ATTR, true, new ThreadLocalOpenTracingStorage().getHeaders(), map);

			Map<String, String> headersToLog = new HashMap<>();

			Map<String, String> headersMap = MDC.getCopyOfContextMap();
			if (headersMap != null) {
				Predicate<String> allCondition = "all"::equalsIgnoreCase;

				// header values
				headersMap.keySet().stream() //
						.forEach(name -> {
							Predicate<String> nameCondition = name::equalsIgnoreCase;

							boolean include = Arrays.stream(includeHeaders).anyMatch(allCondition.or(nameCondition));
							if (include) {
								Object value = MDC.get(name);
								headersToLog.put(name.toLowerCase(), value == null ? "" : value.toString());
							}
						});
			}

			addMap(HEADER_ATTR_NAME, !headersToLog.isEmpty(), headersToLog, map); // add headers to log
		} catch (Exception e) {
			e.printStackTrace(); // We are in a log class so can't use logger!
		}

		super.addCustomDataToJsonMap(map, event);
	}

	/**
	 * this method prints information about configuration errors, if encountered
	 */
	@Override
	public void start() {
		final String PREFIX = "Config option '";

		configErrors.keySet().stream().forEach(key -> {
			Exception e = configErrors.get(key);
			if (e instanceof IllegalArgumentException) {
				addError(PREFIX.concat(key).concat("'").concat(" -> ").concat(e.getMessage()));
			} else {
				addError(PREFIX.concat(key).concat("'"), e);
			}
		});

		synchronized (configErrors) {
			configErrors.clear(); // I think, it is a good idea to print the error one time only!
		}

		super.start();
	}

	/**
	 * this method evaluates the configuration to print or hide many keycloak account attributes according to the logback.xml configuration.
	 * 
	 * @param evaluate
	 *            EvaluateOption
	 * @param authentication
	 *            Spring auth
	 * @return true (means: print) or false (means: hide)
	 */
	private static boolean asBoolean(EvaluateOption evaluate, Authentication authentication) {
		evaluate = evaluate == null ? EvaluateOption.AUTH_ONLY : evaluate; // default value

		boolean flag = true;

		switch (evaluate) {
			case AUTH_ONLY:
				flag = authentication != null;
				break;

			case TRUE:
				flag = true;
				break;

			default:
				flag = false;
		}

		return flag;
	}

	@Override
	protected Map toJsonMap(ILoggingEvent event) {
		Map map = super.toJsonMap(event);
		map.remove(MDC_ATTR_NAME); // removed MDC mapping: we don't want it into json log!
		return map;
	}
}