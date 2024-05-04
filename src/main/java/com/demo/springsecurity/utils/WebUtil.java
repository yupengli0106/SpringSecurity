package com.demo.springsecurity.utils;

import com.alibaba.fastjson.JSON;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 16:40
 * @Description: Web工具类,用于渲染JSON数据。
 * 由于Spring Security的异常处理类只能返回字符串，但是我们需要返回我们自定义的ResponseResult对象,且ResponseResult对象需要转换为JSON字符串。
 * 所以我们需要一个工具类来将对象渲染为JSON字符串,然后返回给前端。
 */

public class WebUtil {
    /**
     * Renders an object as JSON to the HTTP response.
     *
     * @param response the HTTP response object
     * @param object the object to render as JSON
     */
    public static void renderJson(HttpServletResponse response, Object object) {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            String json = JSON.toJSONString(object);
            response.getWriter().write(json);
        } catch (IOException e) {
            // Log the exception if any
            e.printStackTrace();
        }
    }
}

