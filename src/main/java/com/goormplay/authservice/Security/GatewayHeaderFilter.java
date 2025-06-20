package com.goormplay.authservice.Security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;

@Slf4j
public class GatewayHeaderFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        log.info("request : 요청 들어옴");
        String fromGateway = request.getHeader("X-From-Gateway");
        log.info("auth-service GatewayHeaderFilter - X-From-Gateway header: " + fromGateway);
        if (!"true".equals(fromGateway)) {
            log.warn("Invalid X-From-Gateway header!");
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Invalid Request");
        }
        chain.doFilter(req, res); // 다음 필터로 요청 전달
    }
}