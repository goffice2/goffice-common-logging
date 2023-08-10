/*
 * goffice... 
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

import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import ch.qos.logback.classic.spi.ILoggingEvent;

/**
 *
 * <p>
 * The <code>JsonLayout</code> class
 * </p>
 * <p>
 * Data: Jan 4, 2022
 * </p>
 * 
 * @author <a href="mailto:edv@gvcc.net"></a>
 * @version 1.0
 */
public class JsonLayout extends ch.qos.logback.contrib.json.classic.JsonLayout {

	private static final Logger LOGGER = LoggerFactory.getLogger(JsonLayout.class);

	private static final String DEFAULT_INCLUDE_FLAG = "auth-only";

	public static final String USER_ACOUNT_ATTR_NAME = "user.account";
	public static final String USER_ROLES_ATTR_NAME = "user.roles";
	public static final String USER_REAML_ATTR_NAME = "user.realm";
	public static final String USER_EMAIL_ATTR_NAME = "user.email";
	public static final String USER_CLAIMS_ATTR_NAME = "user.claims";

	protected Boolean includeUserAccount;
	protected Boolean includeUserRoles;
	protected Boolean includeUserRealm;
	protected Boolean includeUserEmail;
	protected Boolean includeUserClaims;

	public String getIncludeUserAccount() {
		return toString(includeUserAccount);
	}

	public void setIncludeUserAccount(String includeUserAccount) {
		this.includeUserAccount = parseInclude(includeUserAccount);
	}

	public String getIncludeUserRoles() {
		return toString(includeUserRoles);
	}

	public void setIncludeUserRoles(String includeUserRoles) {
		this.includeUserRoles = parseInclude(includeUserRoles);
	}

	public String getIncludeUserRealm() {
		return toString(includeUserRealm);
	}

	public void setIncludeUserRealm(String includeUserRealm) {
		this.includeUserRealm = parseInclude(includeUserRealm);
	}

	public String getIncludeUserEmail() {
		return toString(includeUserEmail);
	}

	public void setIncludeUserEmail(String includeUserEmail) {
		this.includeUserEmail = parseInclude(includeUserEmail);
	}

	public String getIncludeUserClaims() {
		return toString(includeUserClaims);
	}

	public void setIncludeUserClaims(String includeUserClaims) {
		this.includeUserClaims = parseInclude(includeUserClaims);
	}

	@Override
	protected void addCustomDataToJsonMap(Map<String, Object> map, ILoggingEvent event) {
		LOGGER.trace("START");

		String userAccount = "<anonymous>";
		String roles = "";
		String realm = "<unknown>";
		String email = "";
		Map<String, Object> claims = null;

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("authentication: " + authentication);
		}

		if (authentication != null) {
			userAccount = StringUtils.defaultIfBlank(authentication.getName(), userAccount);
			SimpleKeycloakAccount account = (SimpleKeycloakAccount) authentication.getDetails();
			Set<String> accountRoles = account == null ? null : account.getRoles();
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

		add(USER_ACOUNT_ATTR_NAME, evalInclude(this.includeUserAccount, authentication), userAccount, map);
		add(USER_ROLES_ATTR_NAME, evalInclude(this.includeUserRoles, authentication), roles, map);
		add(USER_REAML_ATTR_NAME, evalInclude(this.includeUserRealm, authentication), realm, map);
		add(USER_EMAIL_ATTR_NAME, evalInclude(this.includeUserEmail, authentication), email, map);
		addMap(USER_CLAIMS_ATTR_NAME, evalInclude(this.includeUserClaims, authentication), claims, map);

		super.addCustomDataToJsonMap(map, event);

		LOGGER.trace("END");
	}

	private static boolean parseInclude(String include) {
		LOGGER.trace("START");

		Boolean flag = null; // default value: means DEFAULT_INCLUDE_FLAG

		if (!DEFAULT_INCLUDE_FLAG.equalsIgnoreCase(include)) {
			flag = Boolean.valueOf(include);
		}

		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("include flag: " + flag);
		}

		LOGGER.trace("END");

		return flag;
	}

	private static String toString(Boolean include) {
		return include == null ? DEFAULT_INCLUDE_FLAG : include.toString();
	}

	private static boolean evalInclude(Boolean include, Authentication authentication) {
		return (include == null && authentication != null) || Boolean.TRUE == include;
	}
}