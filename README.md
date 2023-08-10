<?xml version="1.0" encoding="UTF-8"?>
<configuration>
	<appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
		<encoder class="ch.qos.logback.core.encoder.LayoutWrappingEncoder">

			<layout class="net.gvcc.goffice.logger.JsonLayout">
				<includeUserAccount>true</includeUserAccount>
				<includeUserPrincipal>true</includeUserPrincipal>

				<timestampFormat>yyyy-MM-dd'T'HH:mm:ss.SSSX</timestampFormat>
				<timestampFormatTimezoneId>Etc/UTC</timestampFormatTimezoneId>
				<jsonFormatter
					class="ch.qos.logback.contrib.jackson.JacksonJsonFormatter">
					<prettyPrint>false</prettyPrint>
				</jsonFormatter>
				<appendLineSeparator>true</appendLineSeparator> <!-- don't forget line break -->
			</layout>
		</encoder>
	</appender>
	<appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
		....