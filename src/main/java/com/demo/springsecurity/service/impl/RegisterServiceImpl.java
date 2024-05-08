package com.demo.springsecurity.service.impl;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.mapper.SystemUserMapper;
import com.demo.springsecurity.mapper.SystemUserRoleMapper;
import com.demo.springsecurity.pojo.SystemUser;
import com.demo.springsecurity.service.RegisterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 14:08
 * @Description: Register new user
 */
@Service
public class RegisterServiceImpl implements RegisterService {
    @Autowired
    private SystemUserMapper systemUserMapper;

    @Autowired
    private SystemUserRoleMapper systemUserRoleMapper;

    @Autowired
    private BCryptPasswordEncoder PasswordEncoder;

    @Override
    public ResponseResult registerNewUser(SystemUser newUser) {
        String username = newUser.getUsername();
        String password = newUser.getPassword();
        String hashPassword = PasswordEncoder.encode(password);

        // Check if the username already exists
        if (systemUserMapper.findByUsername(username) != null) {
            return ResponseResult.error(400, "用户名已存在");
        }

        //insert new user into database
        systemUserMapper.insertNewUser(username, hashPassword);
        //get the user id
        SystemUser user = systemUserMapper.findByUsername(username);
        if (user == null) {
            return ResponseResult.error(500, "用户注册失败");
        }

        //set default role for the new user
        Long userID = user.getId();
        systemUserRoleMapper.setDefaultRole(userID);

        return ResponseResult.success("注册成功");
    }
}