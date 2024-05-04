package com.demo.springsecurity.students;

import com.demo.springsecurity.mapper.MenuMapper;
import com.demo.springsecurity.mapper.StudentsMapper;
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
public class StudentsTest {
    @Autowired
    LoginService loginService;
    @Autowired
    StudentsMapper studentsMapper;
    @Autowired
    MenuMapper menuMapper;


    @Test
    public void BcryptTest() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String encode = bCryptPasswordEncoder.encode("test");
        System.out.println(encode);

        boolean matches = bCryptPasswordEncoder.matches("123456", "$2a$10$9.LLyzSmR3tS2hElX3VpW.xlw8by4oY.lzSWFAOjsrdscflDiuLCG");
        System.out.println(matches);
    }

    @Test
    public void testMenuMapper() {
        List<String> strings = menuMapper.selectPermsByUserId(1L);
        System.out.println(strings);

    }
}
