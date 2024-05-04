package com.demo.springsecurity.service.impl;

import com.demo.springsecurity.mapper.MenuMapper;
import com.demo.springsecurity.mapper.StudentsMapper;
import com.demo.springsecurity.pojo.LoginUser;
import com.demo.springsecurity.pojo.Students;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 17:51
 * @Description:
 */
@Service
public class UserDetailServiceImpl implements UserDetailsService{
    @Autowired
    StudentsMapper studentsMapper;
    @Resource
    private MenuMapper menuMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //查询用户的信息在我们的数据库中，而不是在内存中
        //这里我们使用我们自己的数据库来查询用户信息
        Students user = studentsMapper.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }else {
            // 把我们上面查到的用户信息封装到我们自己的LoginUser中
            // 这里我们先写死权限，在实际开发中，我们可以通过查询数据库来获取用户的权限
//            List<String> permissions = new ArrayList<>(Arrays.asList("test","admin"));

            //这里就是实际开发中，通过查询数据库来获取用户的权限
            List<String> permissions = menuMapper.selectPermsByUserId(user.getStudentID().longValue());
            return new LoginUser(user,permissions);
        }
    }
}
