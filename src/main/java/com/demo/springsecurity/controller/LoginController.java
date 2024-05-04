package com.demo.springsecurity.controller;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.pojo.SystemUser;
import com.demo.springsecurity.service.LoginService;
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
    LoginService loginService;

    @PostMapping("/login")
    public ResponseResult login(@RequestBody SystemUser student){
        return loginService.login(student);
    }

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/permission")
    @PreAuthorize("hasAnyAuthority('sys:test:list')")
    public String auth(){
//        [sys:dept:list, sys:test:list]
        return "permission test";
    }

    @GetMapping("/logout")
    public ResponseResult logout(HttpServletRequest request){
        return loginService.logout(request.getHeader("Authorization"));
    }

}
