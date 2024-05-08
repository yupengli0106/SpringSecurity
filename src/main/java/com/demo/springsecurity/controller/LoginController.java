package com.demo.springsecurity.controller;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.pojo.SystemUser;
import com.demo.springsecurity.service.LoginService;
import com.demo.springsecurity.service.RegisterService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * @Author: Yupeng Li
 * @Date: 15/4/2024 20:18
 * @Description:
 */

@RestController
@RequestMapping("/users")
public class LoginController {
    @Autowired
    private LoginService loginService;

    @Autowired
    private RegisterService registerService;

    @PostMapping("/login")
    public ResponseResult login(@RequestBody SystemUser user){
        return loginService.login(user);
    }

    @PostMapping("/register")
    public ResponseResult registerNewUser(@RequestBody SystemUser user){
        return registerService.registerNewUser(user);
    }

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/permission")
    @PreAuthorize("hasAnyAuthority('sys:dept:user')")
    public String auth(){
//        [sys:dept:list, sys:test:list]
        return "permission test";
    }

    @GetMapping("/logout")
    public ResponseResult logout(HttpServletRequest request){
        return loginService.logout(request.getHeader("Authorization"));
    }

}
