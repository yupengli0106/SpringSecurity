package com.demo.springsecurity.handler;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.utils.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 16:37
 * @Description:
 */

@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // 自定义认证失败的返回结果
        ResponseResult errorResult = ResponseResult.error(401, "认证失败，请重新登录");
        // 处理异常，将结果转换为JSON字符串
        WebUtil.renderJson(response, errorResult);

    }
}
