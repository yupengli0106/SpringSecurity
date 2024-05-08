package com.demo.springsecurity.service;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.pojo.SystemUser;

/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 14:07
 * @Description:
 */
public interface RegisterService {
    ResponseResult registerNewUser(SystemUser user);
}
