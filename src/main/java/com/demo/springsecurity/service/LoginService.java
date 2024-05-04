package com.demo.springsecurity.service;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.pojo.Students;
import jakarta.servlet.http.HttpServletRequest;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:23
 * @Description:
 */
public interface LoginService {
    ResponseResult login(Students student);

    ResponseResult logout(String token);
}
