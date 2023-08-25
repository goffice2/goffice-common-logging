package net.gvcc.goffice.logger.test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;

/**
 *
 * <p>
 * The <code>GOfficeJsonLayoutTest</code> class
 * </p>
 * <p>
 * Data: Jun 17, 2022
 * </p>
 * 
 * @author <a href="mailto:renzo.poli@sidera.it">Renzo Poli</a>
 * @version 2.0.3
 */

@SpringBootTest(classes = { GOfficeJsonLayoutTest.class })
class GOfficeJsonLayoutTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(GOfficeJsonLayoutTest.class);

	@Test
	void testLogAsJson() {
		LOGGER.info("START");
		LOGGER.error("do print something!");
		LOGGER.info("END");

		assertNotNull(LOGGER);
	}
}
