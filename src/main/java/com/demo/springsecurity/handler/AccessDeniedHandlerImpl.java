package com.demo.springsecurity.handler;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.utils.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 16:57
 * @Description:
 */
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 自定义权限不足的返回结果
        ResponseResult responseResult = ResponseResult.error(403, "权限不足，请联系管理员");
        // 处理异常，将结果转换为JSON字符串
        WebUtil.renderJson(response, responseResult);
    }
}
