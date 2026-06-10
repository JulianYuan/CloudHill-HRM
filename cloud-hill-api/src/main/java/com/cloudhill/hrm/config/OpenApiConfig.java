package com.cloudhill.hrm.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI(@Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping) {
        String authName = "Authorization";
        // 统计所有接口数量
        long apiNum = handlerMapping.getHandlerMethods().size();

        return new OpenAPI()
                .info(new Info()
                        .title("云山HR管理系统 API文档")
                        .version("v4.3")
                        .description("云山HR（CloudHill HRM）是一个功能完整的人力资源管理系统，包含组织人事、权限控制、考勤管理、薪酬管理、招聘管理等核心模块。")
                        .summary("当前项目接口总数：" + apiNum)
                        .contact(new Contact()
                                .name("CloudHill HRM Team")
                                .email("yuanjulian@qq.com"))
                        .license(new License()
                                .name("MIT")
                                .url("https://mit-license.org/")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:10095")
                                .description("开发环境")
                ))
                .addSecurityItem(new SecurityRequirement().addList(authName))
                .components(new Components()
                        .addSecuritySchemes(authName,
                                new SecurityScheme()
                                        .name(authName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")));
    }
}