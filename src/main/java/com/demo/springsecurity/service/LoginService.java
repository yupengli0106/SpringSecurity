package com.demo.springsecurity.service;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.pojo.SystemUser;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:23
 * @Description:
 */
public interface LoginService {
    ResponseResult login(SystemUser student);

    ResponseResult logout(String token);
}
