package com.saltyfish;

import de.codecentric.boot.admin.server.config.EnableAdminServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * @author: 番薯(Amos)
 * @dateTime: 9:51/25:07:2022
 * @version: v1.0
 * @description: 服务启动入口
 */
@EnableAdminServer
@SpringBootApplication
public class ServerStartApplication {
    
    private static final Logger logger = LoggerFactory.getLogger(ServerStartApplication.class);
    
    public static void main(String[] args) {
        try {
            ConfigurableApplicationContext run = SpringApplication.run(ServerStartApplication.class, args);
            logger.info("{} 服务启动成功; 端口号: {}", run.getEnvironment().getProperty("spring.application.name"),
                    run.getEnvironment().getProperty("server.port"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
