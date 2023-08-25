/*
 * https://www.goffice.it
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
package net.gvcc.goffice.logger.headers.interceptor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author renzo.poli
 *
 */
@Component
public class RequestHeadersLoggingInterceptor implements HandlerInterceptor {
	private static Logger LOGGER = LoggerFactory.getLogger(RequestHeadersLoggingInterceptor.class);

	private static final Predicate<String> NO_FILTER = new Predicate<String>() {

		@Override
		public boolean test(String t) {
			return true;
		}
	};

	/**
	 * The standard method used by springframework to run the custom code before executing an action
	 * <p>
	 * We use it for fill headers storage
	 * 
	 * @param request
	 *            current HTTP request
	 * @param response
	 *            current HTTP response
	 * @param handler
	 *            chosen handler to execute, for type and/or instance evaluation
	 * @return {@code true} if the execution chain should proceed with the next interceptor or the handler itself. Else, DispatcherServlet assumes that this interceptor has already dealt with the
	 *         response itself.
	 * @throws Exception
	 *             in case of errors
	 */
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		LOGGER.trace("preHandle - START");

		try {
			Map<String, List<String>> headers = toMap(request, null);
			headers.keySet().stream() //
					.forEach(headerName -> MDC.put(headerName, listToString(headers.get(headerName))));
		} catch (Exception e) {
			LOGGER.error("preHandle", e);
		}

		LOGGER.trace("preHandle - END");

		return true;
	}

	/**
	 * The standard method used by springframework to run the custom code before executing an action.
	 * <p>
	 * We use it for cleaning headers storage
	 * 
	 * @param request
	 *            current HTTP request
	 * @param response
	 *            current HTTP response
	 * @param handler
	 *            the handler (or {@link HandlerMethod}) that started asynchronous execution, for type and/or instance examination
	 * @param modelAndView
	 *            the {@code ModelAndView} that the handler returned (can also be {@code null})
	 * @throws Exception
	 *             in case of errors
	 */
	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
		LOGGER.trace("postHandle - START");

		try {
			Map<String, List<String>> headers = toMap(request, null);
			headers.keySet().stream() //
					.forEach(headerName -> MDC.remove(headerName));
		} catch (Exception e) {
			LOGGER.error("postHandle", e);
		}

		LOGGER.trace("postHandle - END");
	}

	// =================================================================================================== //

	/**
	 * Convert the header request structure into a map of string list
	 * 
	 * @param request
	 *            Current HTTP request
	 * @param filter
	 *            The criteria to filter the headers
	 * @return A map of headers where key is the name of header and the value is a string list of values
	 */
	private static Map<String, List<String>> toMap(HttpServletRequest request, Predicate<String> filter) {
		Map<String, List<String>> headers = new HashMap<>();

		if (request != null) {
			Collections.list(request.getHeaderNames()).stream() //
					.filter(filter == null ? NO_FILTER : filter) //
					.forEach(headerName -> {
						Enumeration<String> values = request.getHeaders(headerName);
						if (values != null) {
							List<String> headerValues = new ArrayList<>();
							Collections.list(values).forEach(value -> headerValues.add(value));
							headers.put(headerName, headerValues);
						}
					});
		}

		return headers;
	}

	private static String listToString(List<String> headerValues) {
		StringBuilder builder = new StringBuilder();

		if (headerValues != null) {
			headerValues.stream().forEach(headerValue -> builder.append(" ").append(headerValue));
		}

		return builder.toString().trim();
	}
}