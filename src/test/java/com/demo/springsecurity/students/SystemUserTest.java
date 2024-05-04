package com.demo.springsecurity.students;

import com.demo.springsecurity.mapper.MenuMapper;
import com.demo.springsecurity.mapper.SystemUserMapper;
import com.demo.springsecurity.service.LoginService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:33
 * @Description:
 */

@SpringBootTest
public class SystemUserTest {
    @Autowired
    LoginService loginService;
    @Autowired
    SystemUserMapper systemUserMapper;
    @Autowired
    MenuMapper menuMapper;


    @Test
    public void BcryptTest() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String encode = bCryptPasswordEncoder.encode("test3");
        System.out.println(encode);

        boolean matches = bCryptPasswordEncoder.matches("test2", "$2a$10$mDY2Bg6/0BuAlnTaDYETcOUYWAoMFK/egsaaVQv4Lrxasvq/2FLbG");
        System.out.println(matches);
    }

    @Test
    public void testSystemUserMapper() {
        System.out.println(systemUserMapper.findByUsername("test2"));
    }

    @Test
    public void testMenuMapper() {
        List<String> strings = menuMapper.selectPermsByUserId(1L);
        System.out.println(strings);
    }



}
